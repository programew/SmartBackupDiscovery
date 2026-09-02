using System.Net;
using System.Runtime.InteropServices;

namespace SmartBackupDiscovery;

public static class NeighborCacheReader
{
    private const int ErrorInsufficientBuffer = 122;

    public static IReadOnlyDictionary<string, string> ReadIpv4()
    {
        try
        {
            if (OperatingSystem.IsWindows()) return ReadWindows();
            if (OperatingSystem.IsLinux()) return ReadLinux();
        }
        catch
        {
            // Neighbor-cache enrichment is best effort; active probes remain authoritative.
        }
        return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    }

    private static IReadOnlyDictionary<string, string> ReadLinux()
    {
        const string path = "/proc/net/arp";
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!File.Exists(path)) return result;

        foreach (string line in File.ReadLines(path).Skip(1))
        {
            string[] fields = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 6 || !IPAddress.TryParse(fields[0], out IPAddress? address)) continue;
            if (!fields[2].Equals("0x2", StringComparison.OrdinalIgnoreCase)) continue;
            string? mac = NormalizeMac(fields[3]);
            if (mac is not null) result[address.ToString()] = mac;
        }
        return result;
    }

    private static IReadOnlyDictionary<string, string> ReadWindows()
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        int size = 0;
        int first = GetIpNetTable(IntPtr.Zero, ref size, false);
        if (first != ErrorInsufficientBuffer || size <= 4) return result;

        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            int status = GetIpNetTable(buffer, ref size, false);
            if (status != 0) return result;
            int count = Marshal.ReadInt32(buffer);
            int rowSize = Marshal.SizeOf<MibIpNetRow>();
            IntPtr current = IntPtr.Add(buffer, sizeof(int));
            for (int i = 0; i < count; i++)
            {
                MibIpNetRow row = Marshal.PtrToStructure<MibIpNetRow>(current);
                current = IntPtr.Add(current, rowSize);
                int macLength = (int)Math.Min(row.PhysicalAddressLength, 8U);
                if (macLength <= 0 || row.PhysicalAddress is null) continue;

                byte[] ipBytes = BitConverter.GetBytes(row.Address);
                string ip = new IPAddress(ipBytes).ToString();
                string? mac = NormalizeMac(string.Join(":", row.PhysicalAddress.Take(macLength).Select(x => x.ToString("X2"))));
                if (mac is not null) result[ip] = mac;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
        return result;
    }

    private static string? NormalizeMac(string value)
    {
        string[] parts = value.Replace('-', ':').Split(':', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length < 6) return null;
        var bytes = new List<byte>();
        foreach (string part in parts)
        {
            if (!byte.TryParse(part, System.Globalization.NumberStyles.HexNumber, null, out byte parsed)) return null;
            bytes.Add(parsed);
        }
        if (bytes.All(x => x == 0) || bytes.All(x => x == 0xFF)) return null;
        return string.Join(":", bytes.Select(x => x.ToString("X2")));
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibIpNetRow
    {
        public uint InterfaceIndex;
        public uint PhysicalAddressLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[]? PhysicalAddress;
        public uint Address;
        public uint Type;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetIpNetTable(IntPtr ipNetTable, ref int size, bool order);
}
