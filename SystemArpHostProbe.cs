using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace SmartBackupDiscovery;

public sealed record ArpProbeObservation(string MacAddress, string InterfaceName, string LocalAddress);

public interface IArpHostProbe
{
    IReadOnlyList<string> Warnings { get; }
    Task<ArpProbeObservation?> ProbeAsync(IPAddress address, int timeoutMilliseconds, CancellationToken cancellationToken);
}

internal sealed record ArpInterface(string Name, int Index, IPAddress Address, Ipv4Cidr Network, byte[] Mac);

// Resolves only selected targets on a connected Ethernet/Wi-Fi subnet. It never
// expands the scan scope, changes routes, or sends an ARP request to a next hop.
public sealed class SystemArpHostProbe : IArpHostProbe
{
    private static readonly SemaphoreSlim WindowsCalls = new(8);
    private readonly Lazy<IReadOnlyList<ArpInterface>> _interfaces = new(ReadInterfaces);
    private readonly Lazy<IReadOnlyList<NetworkRouteHint>> _routes = new(NetworkRouteTableReader.ReadPrivateIpv4Routes);
    private readonly ConcurrentDictionary<string, byte> _warnings = new(StringComparer.Ordinal);
    private int _unavailable;

    public IReadOnlyList<string> Warnings => _warnings.Keys.OrderBy(x => x, StringComparer.Ordinal).ToArray();

    public async Task<ArpProbeObservation?> ProbeAsync(IPAddress address, int timeoutMilliseconds, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (Volatile.Read(ref _unavailable) != 0 || address.AddressFamily != AddressFamily.InterNetwork) return null;
        ArpInterface? link = SelectInterface(address, _interfaces.Value, _routes.Value);
        if (link is null) return null;

        try
        {
            string? mac = OperatingSystem.IsWindows()
                ? await ResolveWindowsAsync(address, link, timeoutMilliseconds, cancellationToken).ConfigureAwait(false)
                : OperatingSystem.IsLinux()
                    ? await ResolveLinuxAsync(address, link, timeoutMilliseconds, cancellationToken).ConfigureAwait(false)
                    : null;
            return mac is null ? null : new ArpProbeObservation(mac, link.Name, link.Address.ToString());
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (ex is Win32Exception or DllNotFoundException or EntryPointNotFoundException or PlatformNotSupportedException)
        {
            Interlocked.Exchange(ref _unavailable, 1);
            _warnings.TryAdd("Active ARP is unavailable: " + ex.Message +
                (OperatingSystem.IsLinux() ? ". Linux packet sockets require CAP_NET_RAW or root." : ".") +
                " Other discovery signals continue.", 0);
            return null;
        }
    }

    internal static ArpInterface? SelectInterface(IPAddress address, IReadOnlyList<ArpInterface> links,
        IReadOnlyList<NetworkRouteHint> routes)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork) return null;
        uint value = Ipv4Cidr.ToUInt32(address);
        var candidates = links.Where(x => x.Network.Contains(address) && !x.Address.Equals(address) &&
                (x.Network.PrefixLength >= 31 || value != x.Network.NetworkValue &&
                    value != (x.Network.NetworkValue | (uint.MaxValue >> x.Network.PrefixLength))))
            .OrderByDescending(x => x.Network.PrefixLength).ThenBy(x => x.Index).ToArray();
        foreach (ArpInterface link in candidates)
        {
            NetworkRouteHint[] matching = routes.Where(x => Ipv4Cidr.Parse(x.Cidr).Contains(address)).ToArray();
            int longest = matching.Length == 0 ? -1 : matching.Max(x => Ipv4Cidr.Parse(x.Cidr).PrefixLength);
            if (longest >= link.Network.PrefixLength)
            {
                NetworkRouteHint[] best = matching.Where(x => Ipv4Cidr.Parse(x.Cidr).PrefixLength == longest).ToArray();
                // Equal-prefix ambiguity is treated conservatively too.
                if (best.Any(x => !x.IsDirect)) continue;
                if (!best.Any(x => x.InterfaceName.Equals(link.Name, StringComparison.OrdinalIgnoreCase) ||
                    x.InterfaceName.Equals($"ifIndex:{link.Index}", StringComparison.OrdinalIgnoreCase))) continue;
            }
            return link;
        }
        return null;
    }

    private static IReadOnlyList<ArpInterface> ReadInterfaces()
    {
        var result = new List<ArpInterface>();
        foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (adapter.OperationalStatus != OperationalStatus.Up ||
                adapter.NetworkInterfaceType is not (NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211)) continue;
            try
            {
                byte[] mac = adapter.GetPhysicalAddress().GetAddressBytes();
                if (!IsUnicastMac(mac)) continue;
                IPInterfaceProperties properties = adapter.GetIPProperties();
                int index = properties.GetIPv4Properties().Index;
                foreach (UnicastIPAddressInformation item in properties.UnicastAddresses)
                {
                    if (item.Address.AddressFamily != AddressFamily.InterNetwork || item.PrefixLength is < 1 or > 32) continue;
                    Ipv4Cidr network = Ipv4Cidr.FromAddress(item.Address, item.PrefixLength);
                    if (network.IsPrivateScope()) result.Add(new ArpInterface(adapter.Name, index, item.Address, network, mac));
                }
            }
            catch (NetworkInformationException) { }
        }
        return result;
    }

    private static async Task<string?> ResolveWindowsAsync(IPAddress address, ArpInterface link, int timeoutMilliseconds,
        CancellationToken cancellationToken)
    {
        // Queue every eligible target; timing out while waiting for a native
        // slot would silently skip most addresses on a sparsely populated LAN.
        await WindowsCalls.WaitAsync(cancellationToken).ConfigureAwait(false);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeoutMilliseconds);
        try
        {
            // Windows' synchronous resolver cannot be interrupted. The native
            // worker owns its slot until it ends, including after caller timeout.
            Task<string?> worker = Task.Run(() =>
            {
                try
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var row = new MibIpNetRow2
                    {
                        Address = SockaddrInet.From(address), InterfaceIndex = (uint)link.Index,
                        PhysicalAddress = new byte[32]
                    };
                    SockaddrInet source = SockaddrInet.From(link.Address);
                    uint status = ResolveIpNetEntry2(ref row, ref source);
                    if (status is 5 or 50) throw new Win32Exception((int)status);
                    // ResolveIpNetEntry2 refreshes this neighbor, rather than
                    // treating an old cached/static address as a fresh response.
                    return status == 0 && row.PhysicalAddressLength == 6 && row.State == 5 && (row.Flags & 2) == 0 &&
                        IsUnicastMac(row.PhysicalAddress.AsSpan(0, 6))
                        ? FormatMac(row.PhysicalAddress.AsSpan(0, 6)) : null;
                }
                finally { WindowsCalls.Release(); }
            });
            // Observe faults even if the caller times out before native completion.
            _ = worker.ContinueWith(t => { _ = t.Exception; }, CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            return await worker.WaitAsync(deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return null; }
    }

    private static async Task<string?> ResolveLinuxAsync(IPAddress address, ArpInterface link, int timeoutMilliseconds,
        CancellationToken cancellationToken)
    {
        const int afPacket = 17, sockDgram = 2, nonBlocking = 0x800, closeOnExec = 0x80000;
        ushort protocol = BitConverter.IsLittleEndian ? (ushort)0x0608 : (ushort)0x0806;
        int fd = LinuxSocket(afPacket, sockDgram | nonBlocking | closeOnExec, protocol);
        if (fd < 0) throw new Win32Exception(Marshal.GetLastPInvokeError(), "Could not open the Linux ARP packet socket");
        try
        {
            var endpoint = new SockaddrLl
            {
                Family = afPacket, Protocol = protocol, InterfaceIndex = link.Index,
                HardwareAddressLength = 6, Address = new byte[] { 255, 255, 255, 255, 255, 255, 0, 0 }
            };
            uint endpointSize = (uint)Marshal.SizeOf<SockaddrLl>();
            if (LinuxBind(fd, ref endpoint, endpointSize) != 0)
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "Could not bind the Linux ARP packet socket");
            byte[] request = BuildRequest(link.Mac, link.Address, address);
            byte[] buffer = new byte[128];
            long started = Stopwatch.GetTimestamp();
            int sends = 0;
            while (Stopwatch.GetElapsedTime(started).TotalMilliseconds < timeoutMilliseconds)
            {
                cancellationToken.ThrowIfCancellationRequested();
                double elapsed = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
                if (sends == 0 || sends == 1 && elapsed >= timeoutMilliseconds / 2.0)
                {
                    if (LinuxSendTo(fd, request, (nuint)request.Length, 0, ref endpoint, endpointSize) != request.Length)
                        throw new Win32Exception(Marshal.GetLastPInvokeError(), "Could not send the Linux ARP request");
                    sends++;
                }
                // Bound receive work as well as sends; busy LANs cannot extend
                // this probe indefinitely or starve cancellation.
                for (int i = 0; i < 32; i++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    nint count = LinuxReceive(fd, buffer, (nuint)buffer.Length, 0);
                    if (count < 0)
                    {
                        int error = Marshal.GetLastPInvokeError();
                        if (error is 11 or 4) break; // EAGAIN/EINTR
                        throw new Win32Exception(error, "Could not receive the Linux ARP reply");
                    }
                    string? mac = ParseReply(buffer.AsSpan(0, (int)count), link.Mac, link.Address, address);
                    if (mac is not null) return mac;
                    if (Stopwatch.GetElapsedTime(started).TotalMilliseconds >= timeoutMilliseconds) break;
                }
                int remaining = timeoutMilliseconds - (int)Stopwatch.GetElapsedTime(started).TotalMilliseconds;
                if (remaining > 0) await Task.Delay(Math.Min(20, remaining), cancellationToken).ConfigureAwait(false);
            }
            return null;
        }
        finally { LinuxClose(fd); }
    }

    internal static byte[] BuildRequest(byte[] mac, IPAddress source, IPAddress target)
    {
        var packet = new byte[28];
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(0, 2), 1); // Ethernet
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), 0x0800); // IPv4
        packet[4] = 6; packet[5] = 4;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(6, 2), 1); // request
        mac.CopyTo(packet, 8);
        source.GetAddressBytes().CopyTo(packet, 14);
        target.GetAddressBytes().CopyTo(packet, 24);
        return packet;
    }

    internal static string? ParseReply(ReadOnlySpan<byte> packet, byte[] localMac, IPAddress source, IPAddress target)
    {
        if (packet.Length < 28 || BinaryPrimitives.ReadUInt16BigEndian(packet[..2]) != 1 ||
            BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(2, 2)) != 0x0800 || packet[4] != 6 || packet[5] != 4 ||
            BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(6, 2)) != 2 ||
            !packet.Slice(14, 4).SequenceEqual(target.GetAddressBytes()) ||
            !packet.Slice(24, 4).SequenceEqual(source.GetAddressBytes()) ||
            !packet.Slice(18, 6).SequenceEqual(localMac) || !IsUnicastMac(packet.Slice(8, 6))) return null;
        return FormatMac(packet.Slice(8, 6));
    }

    internal static bool IsUnicastMac(ReadOnlySpan<byte> mac) => mac.Length == 6 && (mac[0] & 1) == 0 &&
        !mac.SequenceEqual(new byte[6]);
    private static string FormatMac(ReadOnlySpan<byte> mac) => string.Join(":", mac.ToArray().Select(x => x.ToString("X2")));

    internal static bool NativeLayoutsAreValid() => Marshal.SizeOf<SockaddrInet>() == 28 &&
        Marshal.SizeOf<MibIpNetRow2>() == 88 && Marshal.OffsetOf<MibIpNetRow2>(nameof(MibIpNetRow2.PhysicalAddress)).ToInt32() == 40 &&
        Marshal.SizeOf<SockaddrLl>() == 20;

    [StructLayout(LayoutKind.Sequential)]
    private struct SockaddrInet
    {
        public ushort Family;
        public ushort Port;
        public uint Address;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)] public byte[] Tail;
        public static SockaddrInet From(IPAddress address) => new()
        {
            Family = 2, Address = BitConverter.ToUInt32(address.GetAddressBytes()), Tail = new byte[20]
        };
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibIpNetRow2
    {
        public SockaddrInet Address;
        public uint InterfaceIndex;
        public ulong InterfaceLuid;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] PhysicalAddress;
        public uint PhysicalAddressLength;
        public uint State;
        public byte Flags;
        public uint ReachabilityTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SockaddrLl
    {
        public ushort Family;
        public ushort Protocol;
        public int InterfaceIndex;
        public ushort HardwareType;
        public byte PacketType;
        public byte HardwareAddressLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public byte[] Address;
    }

    [DllImport("iphlpapi.dll")]
    private static extern uint ResolveIpNetEntry2(ref MibIpNetRow2 row, ref SockaddrInet source);
    [DllImport("libc", EntryPoint = "socket", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
    private static extern int LinuxSocket(int domain, int type, int protocol);
    [DllImport("libc", EntryPoint = "bind", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
    private static extern int LinuxBind(int fd, ref SockaddrLl address, uint length);
    [DllImport("libc", EntryPoint = "sendto", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
    private static extern nint LinuxSendTo(int fd, byte[] data, nuint length, int flags, ref SockaddrLl address, uint addressLength);
    [DllImport("libc", EntryPoint = "recv", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
    private static extern nint LinuxReceive(int fd, [Out] byte[] data, nuint length, int flags);
    [DllImport("libc", EntryPoint = "close", CallingConvention = CallingConvention.Cdecl)]
    private static extern int LinuxClose(int fd);
}
