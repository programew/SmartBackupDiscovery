using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace SmartBackupDiscovery;

public readonly record struct Ipv4Cidr
{
    private Ipv4Cidr(uint networkValue, int prefixLength)
    {
        NetworkValue = networkValue;
        PrefixLength = prefixLength;
    }

    internal uint NetworkValue { get; }
    public int PrefixLength { get; }
    public IPAddress NetworkAddress => FromUInt32(NetworkValue);
    public string Canonical => $"{NetworkAddress}/{PrefixLength}";

    public ulong UsableAddressCount
    {
        get
        {
            ulong total = 1UL << (32 - PrefixLength);
            return PrefixLength switch
            {
                32 => 1,
                31 => 2,
                _ => total - 2
            };
        }
    }

    public static Ipv4Cidr Parse(string input)
    {
        if (!TryParse(input, out Ipv4Cidr result))
            throw new ArgumentException($"Invalid IPv4 CIDR '{input}'. Use a value such as 192.168.1.0/24.");
        return result;
    }

    public static bool TryParse(string? input, out Ipv4Cidr result)
    {
        result = default;
        if (string.IsNullOrWhiteSpace(input)) return false;
        string[] parts = input.Trim().Split('/', 2, StringSplitOptions.TrimEntries);
        if (parts.Length != 2 ||
            !IPAddress.TryParse(parts[0], out IPAddress? address) ||
            address.AddressFamily != AddressFamily.InterNetwork ||
            !int.TryParse(parts[1], out int prefix) ||
            prefix is < 0 or > 32)
            return false;

        uint value = ToUInt32(address);
        uint mask = PrefixMask(prefix);
        result = new Ipv4Cidr(value & mask, prefix);
        return true;
    }

    public static Ipv4Cidr FromAddress(IPAddress address, int prefixLength)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("Only IPv4 scopes are supported in network inventory v1.", nameof(address));
        if (prefixLength is < 0 or > 32)
            throw new ArgumentOutOfRangeException(nameof(prefixLength));
        return new Ipv4Cidr(ToUInt32(address) & PrefixMask(prefixLength), prefixLength);
    }

    public bool Contains(IPAddress address) =>
        address.AddressFamily == AddressFamily.InterNetwork &&
        (ToUInt32(address) & PrefixMask(PrefixLength)) == NetworkValue;

    public bool Contains(uint addressValue) =>
        (addressValue & PrefixMask(PrefixLength)) == NetworkValue;

    public IEnumerable<IPAddress> EnumerateUsableAddresses()
    {
        ulong blockSize = 1UL << (32 - PrefixLength);
        ulong first = NetworkValue;
        ulong last = first + blockSize - 1;
        if (PrefixLength <= 30)
        {
            first++;
            last--;
        }

        for (ulong current = first; current <= last; current++)
            yield return FromUInt32((uint)current);
    }

    public bool IsPrivateScope()
    {
        ulong blockSize = 1UL << (32 - PrefixLength);
        uint first = NetworkValue;
        uint last = (uint)(NetworkValue + blockSize - 1);
        return PrivateBlock(first) is { } block && block == PrivateBlock(last);
    }

    public override string ToString() => Canonical;

    internal static uint ToUInt32(IPAddress address)
    {
        byte[] bytes = address.GetAddressBytes();
        if (bytes.Length != 4) throw new ArgumentException("IPv4 address required.", nameof(address));
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }

    internal static IPAddress FromUInt32(uint value) => new(new[]
    {
        (byte)(value >> 24),
        (byte)(value >> 16),
        (byte)(value >> 8),
        (byte)value
    });

    private static uint PrefixMask(int prefixLength) =>
        prefixLength == 0 ? 0U : uint.MaxValue << (32 - prefixLength);

    private static int? PrivateBlock(uint value)
    {
        if ((value & 0xFF000000U) == 0x0A000000U) return 10;            // 10.0.0.0/8
        if ((value & 0xFFF00000U) == 0xAC100000U) return 172;           // 172.16.0.0/12
        if ((value & 0xFFFF0000U) == 0xC0A80000U) return 192;           // 192.168.0.0/16
        return null;
    }
}

public static class NetworkScopePlanner
{
    public static IReadOnlyList<NetworkDiscoveryScope> ResolveScopes(
        IReadOnlyList<string> explicitCidrs,
        bool includeLocalScopes,
        bool explicitScopeAuthorized,
        List<string> warnings,
        List<NetworkScopeSuggestion>? suggestions = null)
    {
        if (explicitCidrs.Count > 0 && !explicitScopeAuthorized)
            throw new ArgumentException("Explicit --cidr scopes require --authorized-scope to confirm that you are authorized to inventory them.");

        var scopes = new Dictionary<string, NetworkDiscoveryScope>(StringComparer.OrdinalIgnoreCase);
        if (explicitCidrs.Count == 0 || includeLocalScopes)
        {
            foreach (NetworkDiscoveryScope scope in GetLocalPrivateScopes(warnings))
                scopes.TryAdd(scope.Cidr, scope);

            foreach (NetworkRouteHint route in NetworkRouteTableReader.ReadPrivateIpv4Routes())
            {
                if (scopes.ContainsKey(route.Cidr)) continue;
                Ipv4Cidr cidr = Ipv4Cidr.Parse(route.Cidr);
                if (route.IsDirect && cidr.PrefixLength >= 20)
                {
                    scopes.TryAdd(route.Cidr, new NetworkDiscoveryScope(
                        route.Cidr,
                        "LocalDirectRoute",
                        route.InterfaceName,
                        null,
                        checked((long)cidr.UsableAddressCount),
                        false));
                    continue;
                }

                suggestions?.Add(new NetworkScopeSuggestion(
                    route.Cidr,
                    route.IsDirect ? "BroadDirectRoute" : "PrivateRoute",
                    route.IsDirect
                        ? "A broad private directly connected route exists; it was not automatically expanded because of its size."
                        : "A private route exists through a next hop; review scope and authorization before active inventory.",
                    new[] { $"interface={route.InterfaceName}", $"nextHop={route.NextHop ?? "direct"}" },
                    false));
            }
        }

        foreach (string raw in explicitCidrs)
        {
            Ipv4Cidr cidr = Ipv4Cidr.Parse(raw);
            if (!cidr.IsPrivateScope())
                throw new ArgumentException($"Explicit scope '{raw}' is not wholly inside an RFC1918 private IPv4 range. Network inventory refuses public-address scopes.");
            scopes[cidr.Canonical] = new NetworkDiscoveryScope(
                cidr.Canonical,
                "ExplicitCidr",
                null,
                null,
                checked((long)cidr.UsableAddressCount),
                true);
        }

        if (scopes.Count == 0)
            throw new InvalidOperationException("No eligible private IPv4 network scope was found. Supply an authorized private scope with --cidr <network/prefix> --authorized-scope.");

        return scopes.Values.OrderBy(x => Ipv4Cidr.Parse(x.Cidr).NetworkValue).ThenBy(x => x.Cidr, StringComparer.Ordinal).ToArray();
    }

    public static IReadOnlyList<Ipv4Cidr> ParseExclusions(IReadOnlyList<string> exclusions) =>
        exclusions.Select(Ipv4Cidr.Parse).Distinct().ToArray();

    private static IEnumerable<NetworkDiscoveryScope> GetLocalPrivateScopes(List<string> warnings)
    {
        foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces()
                     .OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase))
        {
            if (adapter.OperationalStatus != OperationalStatus.Up ||
                adapter.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                continue;

            IPInterfaceProperties properties;
            try { properties = adapter.GetIPProperties(); }
            catch (Exception ex)
            {
                warnings.Add($"Could not inspect network adapter '{adapter.Name}': {ex.Message}");
                continue;
            }

            foreach (UnicastIPAddressInformation unicast in properties.UnicastAddresses)
            {
                if (unicast.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                int prefix = unicast.PrefixLength;
                if (prefix is < 1 or > 32) continue;
                Ipv4Cidr cidr = Ipv4Cidr.FromAddress(unicast.Address, prefix);
                if (!cidr.IsPrivateScope())
                {
                    warnings.Add($"Skipped non-private connected scope {cidr.Canonical} on adapter '{adapter.Name}'.");
                    continue;
                }

                yield return new NetworkDiscoveryScope(
                    cidr.Canonical,
                    "LocalInterface",
                    adapter.Name,
                    unicast.Address.ToString(),
                    checked((long)cidr.UsableAddressCount),
                    false);
            }
        }
    }
}
