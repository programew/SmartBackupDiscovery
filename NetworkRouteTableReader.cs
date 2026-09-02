using System.Net;
using System.Runtime.InteropServices;

namespace SmartBackupDiscovery;

public sealed record NetworkRouteHint(
    string Cidr,
    string InterfaceName,
    string? NextHop,
    bool IsDirect);

public static class NetworkRouteTableReader
{
    private const int ErrorInsufficientBuffer = 122;

    public static IReadOnlyList<NetworkRouteHint> ReadPrivateIpv4Routes()
    {
        try
        {
            IReadOnlyList<NetworkRouteHint> routes = OperatingSystem.IsWindows()
                ? ReadWindows()
                : OperatingSystem.IsLinux()
                    ? ParseLinuxRouteLines(File.Exists("/proc/net/route") ? File.ReadLines("/proc/net/route") : Array.Empty<string>())
                    : Array.Empty<NetworkRouteHint>();
            return routes
                .GroupBy(x => $"{x.Cidr}|{x.InterfaceName}|{x.NextHop}", StringComparer.OrdinalIgnoreCase)
                .Select(x => x.First())
                .OrderBy(x => Ipv4Cidr.Parse(x.Cidr).NetworkValue)
                .ThenByDescending(x => Ipv4Cidr.Parse(x.Cidr).PrefixLength)
                .ToArray();
        }
        catch
        {
            return Array.Empty<NetworkRouteHint>();
        }
    }

    internal static IReadOnlyList<NetworkRouteHint> ParseLinuxRouteLines(IEnumerable<string> lines)
    {
        var result = new List<NetworkRouteHint>();
        foreach (string line in lines)
        {
            string[] fields = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 8 || fields[0].Equals("Iface", StringComparison.OrdinalIgnoreCase)) continue;
            if (!uint.TryParse(fields[3], System.Globalization.NumberStyles.HexNumber, null, out uint flags) || (flags & 0x1U) == 0) continue;
            if (!TryParseLinuxHexAddress(fields[1], out IPAddress? destination) ||
                !TryParseLinuxHexAddress(fields[2], out IPAddress? gateway) ||
                !TryParseLinuxHexAddress(fields[7], out IPAddress? mask) ||
                !TryPrefixLength(mask, out int prefix) || prefix == 0)
                continue;

            Ipv4Cidr cidr = Ipv4Cidr.FromAddress(destination, prefix);
            if (!cidr.IsPrivateScope()) continue;
            bool direct = gateway.Equals(IPAddress.Any);
            result.Add(new NetworkRouteHint(cidr.Canonical, fields[0], direct ? null : gateway.ToString(), direct));
        }
        return result;
    }

    private static IReadOnlyList<NetworkRouteHint> ReadWindows()
    {
        var result = new List<NetworkRouteHint>();
        int size = 0;
        int first = GetIpForwardTable(IntPtr.Zero, ref size, false);
        if (first != ErrorInsufficientBuffer || size <= 4) return result;

        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            int status = GetIpForwardTable(buffer, ref size, false);
            if (status != 0) return result;
            int count = Marshal.ReadInt32(buffer);
            int rowSize = Marshal.SizeOf<MibIpForwardRow>();
            IntPtr current = IntPtr.Add(buffer, sizeof(int));
            for (int i = 0; i < count; i++)
            {
                MibIpForwardRow row = Marshal.PtrToStructure<MibIpForwardRow>(current);
                current = IntPtr.Add(current, rowSize);
                IPAddress destination = new(BitConverter.GetBytes(row.ForwardDestination));
                IPAddress mask = new(BitConverter.GetBytes(row.ForwardMask));
                IPAddress nextHop = new(BitConverter.GetBytes(row.ForwardNextHop));
                if (!TryPrefixLength(mask, out int prefix) || prefix == 0) continue;
                Ipv4Cidr cidr = Ipv4Cidr.FromAddress(destination, prefix);
                if (!cidr.IsPrivateScope()) continue;
                bool direct = nextHop.Equals(IPAddress.Any);
                result.Add(new NetworkRouteHint(cidr.Canonical, $"ifIndex:{row.ForwardInterfaceIndex}", direct ? null : nextHop.ToString(), direct));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
        return result;
    }

    private static bool TryParseLinuxHexAddress(string value, out IPAddress address)
    {
        address = IPAddress.None;
        if (!uint.TryParse(value, System.Globalization.NumberStyles.HexNumber, null, out uint raw)) return false;
        address = new IPAddress(BitConverter.GetBytes(raw));
        return true;
    }

    private static bool TryPrefixLength(IPAddress maskAddress, out int prefix)
    {
        prefix = 0;
        uint mask = Ipv4Cidr.ToUInt32(maskAddress);
        bool zeroSeen = false;
        for (int bit = 31; bit >= 0; bit--)
        {
            bool set = (mask & (1U << bit)) != 0;
            if (set && zeroSeen) return false;
            if (set) prefix++;
            else zeroSeen = true;
        }
        return true;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibIpForwardRow
    {
        public uint ForwardDestination;
        public uint ForwardMask;
        public uint ForwardPolicy;
        public uint ForwardNextHop;
        public uint ForwardInterfaceIndex;
        public uint ForwardType;
        public uint ForwardProtocol;
        public uint ForwardAge;
        public uint ForwardNextHopAs;
        public uint ForwardMetric1;
        public uint ForwardMetric2;
        public uint ForwardMetric3;
        public uint ForwardMetric4;
        public uint ForwardMetric5;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetIpForwardTable(IntPtr forwardTable, ref int size, bool order);
}
