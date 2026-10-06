using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;

namespace SmartBackupDiscovery;

public static partial class SelfTest
{
    private static void RunArpTests(Action<string, Func<bool>> test, string root)
    {
        byte[] localMac = { 0x02, 0x10, 0x20, 0x30, 0x40, 0x50 };
        byte[] remoteMac = { 0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE };
        IPAddress source = IPAddress.Parse("192.168.80.10"), target = IPAddress.Parse("192.168.80.20");
        byte[] Reply()
        {
            var bytes = new byte[28];
            new byte[] { 0, 1, 8, 0, 6, 4, 0, 2 }.CopyTo(bytes, 0);
            remoteMac.CopyTo(bytes, 8); target.GetAddressBytes().CopyTo(bytes, 14);
            localMac.CopyTo(bytes, 18); source.GetAddressBytes().CopyTo(bytes, 24);
            return bytes;
        }

        test("ARP request uses Ethernet IPv4 wire format and the selected source", () =>
        {
            byte[] bytes = SystemArpHostProbe.BuildRequest(localMac, source, target);
            return bytes.Length == 28 && bytes.Take(8).SequenceEqual(new byte[] { 0, 1, 8, 0, 6, 4, 0, 1 }) &&
                bytes.Skip(8).Take(6).SequenceEqual(localMac) && bytes.Skip(14).Take(4).SequenceEqual(source.GetAddressBytes()) &&
                bytes.Skip(18).Take(6).All(x => x == 0) && bytes.Skip(24).SequenceEqual(target.GetAddressBytes());
        });
        test("ARP accepts a matching reply and rejects truncated foreign or invalid packets", () =>
        {
            byte[] valid = Reply();
            if (SystemArpHostProbe.ParseReply(valid, localMac, source, target) != "02:AA:BB:CC:DD:EE") return false;
            var bad = new List<byte[]> { valid[..27] };
            foreach (int offset in new[] { 0, 2, 4, 5, 7, 14, 18, 24 })
            {
                byte[] changed = (byte[])valid.Clone(); changed[offset] ^= 1; bad.Add(changed);
            }
            byte[] multicast = (byte[])valid.Clone(); multicast[8] = 1; bad.Add(multicast);
            byte[] zeroMac = (byte[])valid.Clone(); Array.Clear(zeroMac, 8, 6); bad.Add(zeroMac);
            return bad.All(x => SystemArpHostProbe.ParseReply(x, localMac, source, target) is null);
        });
        test("ARP interop layouts match Windows neighbor rows and Linux sockaddr_ll", SystemArpHostProbe.NativeLayoutsAreValid);
        test("ARP selects a matching connected interface and skips more-specific gateway routes", () =>
        {
            var links = new[]
            {
                new ArpInterface("lan-a", 3, source, Ipv4Cidr.Parse("192.168.80.0/24"), localMac),
                new ArpInterface("lan-b", 7, IPAddress.Parse("192.168.81.10"), Ipv4Cidr.Parse("192.168.81.0/24"), localMac)
            };
            var routes = new[]
            {
                new NetworkRouteHint("192.168.80.0/24", "ifIndex:3", null, true),
                new NetworkRouteHint("192.168.81.0/24", "lan-b", null, true),
                new NetworkRouteHint("192.168.80.30/32", "lan-a", "192.168.80.1", false)
            };
            return SystemArpHostProbe.SelectInterface(target, links, routes)?.Index == 3 &&
                SystemArpHostProbe.SelectInterface(IPAddress.Parse("192.168.81.20"), links, routes)?.Index == 7 &&
                SystemArpHostProbe.SelectInterface(IPAddress.Parse("192.168.80.30"), links, routes) is null &&
                SystemArpHostProbe.SelectInterface(IPAddress.Parse("10.20.0.10"), links, routes) is null;
        });
        test("ARP skips self network and broadcast addresses but supports connected /31", () =>
        {
            var links = new[] { new ArpInterface("lan", 3, source, Ipv4Cidr.Parse("192.168.80.0/24"), localMac) };
            var routes = Array.Empty<NetworkRouteHint>();
            var pointToPoint = new[] { new ArpInterface("lan", 3, IPAddress.Parse("192.168.80.1"), Ipv4Cidr.Parse("192.168.80.0/31"), localMac) };
            return SystemArpHostProbe.SelectInterface(source, links, routes) is null &&
                SystemArpHostProbe.SelectInterface(IPAddress.Parse("192.168.80.0"), links, routes) is null &&
                SystemArpHostProbe.SelectInterface(IPAddress.Parse("192.168.80.255"), links, routes) is null &&
                SystemArpHostProbe.SelectInterface(IPAddress.Parse("192.168.80.0"), pointToPoint, routes) is not null;
        });
        test("fresh ARP finds a host with blocked ICMP and no open service", () =>
        {
            var arp = new FakeArpHostProbe(new Dictionary<string, ArpProbeObservation>
            { ["192.168.80.1"] = new("02:AA:BB:CC:DD:EE", "fixture-lan", "192.168.80.10") });
            NetworkInventoryManifest inventory = Inventory(arp);
            NetworkDiscoveredHost host = inventory.Hosts.Single();
            return host.IpAddress == "192.168.80.1" && host.ArpResolved && host.Reachability == "ArpResolved" &&
                !host.IcmpReachable && host.OpenTcpPorts.Count == 0 && host.MacAddress == "02:AA:BB:CC:DD:EE" &&
                host.ArpInterfaceName == "fixture-lan" && inventory.Summary.ArpResolvedHosts == 1 && inventory.Errors.Count == 0;
        });
        test("fresh ARP overrides an old MAC without promoting a stale cache-only host", () =>
        {
            var arp = new FakeArpHostProbe(new Dictionary<string, ArpProbeObservation>
            { ["192.168.80.1"] = new("02:AA:BB:CC:DD:EE", "fixture-lan", "192.168.80.10") });
            var cache = new Dictionary<string, string> { ["192.168.80.1"] = "00:11:22:33:44:55", ["192.168.80.2"] = "00:11:22:33:44:66" };
            NetworkInventoryManifest inventory = Inventory(arp, () => cache);
            return inventory.Hosts.Single(x => x.IpAddress.EndsWith(".1")).MacAddress == "02:AA:BB:CC:DD:EE" &&
                inventory.Hosts.Single(x => x.IpAddress.EndsWith(".2")).Reachability == "NeighborCacheOnly" &&
                !inventory.Hosts.Single(x => x.IpAddress.EndsWith(".2")).ArpResolved;
        });
        test("active ARP honors exclusions and overlapping scopes without duplicate requests", () =>
        {
            var arp = new FakeArpHostProbe();
            _ = Inventory(arp, scopes: new[] { Scope("192.168.80.0/29"), Scope("192.168.80.0/30") },
                exclusions: new[] { Ipv4Cidr.Parse("192.168.80.2/32"), Ipv4Cidr.Parse("192.168.80.4/30") });
            return arp.Calls.Count == 2 && arp.Calls.Keys.Order().SequenceEqual(new[] { "192.168.80.1", "192.168.80.3" }) &&
                arp.Calls.Values.All(x => x == 1);
        });
        test("disabled ARP makes no resolver calls and rejects a run with every signal disabled", () =>
        {
            var arp = new FakeArpHostProbe();
            _ = Inventory(arp, policy: Policy() with { UseArp = false });
            if (arp.Calls.Count != 0) return false;
            try { _ = Inventory(arp, policy: Policy() with { UseArp = false, ReadNeighborCache = false }); return false; }
            catch (ArgumentException) { return true; }
        });
        test("neighbor cache is refreshed after probes and new entries remain passive and in scope", () =>
        {
            int reads = 0;
            NetworkInventoryManifest inventory = Inventory(new FakeArpHostProbe(), () => ++reads == 1
                ? new Dictionary<string, string>()
                : new Dictionary<string, string>
                {
                    ["192.168.80.1"] = "00:11:22:33:44:55", ["192.168.80.2"] = "00:11:22:33:44:66",
                    ["192.168.81.7"] = "00:11:22:33:44:77"
                }, exclusions: new[] { Ipv4Cidr.Parse("192.168.80.2/32") });
            return reads == 2 && inventory.Hosts.Count == 1 && inventory.Hosts[0].IpAddress == "192.168.80.1" &&
                inventory.Hosts[0].Reachability == "NeighborCacheOnly" && !inventory.Hosts[0].ArpResolved &&
                inventory.SuggestedScopes.Any(x => x.Cidr == "192.168.81.0/24" && !x.ActivelyProbed);
        });
        test("ARP settings preserve old config defaults persist disabled state and allow a CLI override", () =>
        {
            string path = Path.Combine(root, "arp-settings.json");
            var old = JsonSerializer.Deserialize<NetworkConfiguration>("{}", ManifestWriter.Options)!;
            var config = new ScanConfiguration { Network = new NetworkConfiguration { UseArp = false } };
            ScanConfiguration.Save(path, config);
            var (args, loaded) = ScanConfiguration.ExpandArguments(new[] { "network-discover", "--config", path, "--arp" });
            return old.UseArp && loaded is not null && !loaded.Network.UseArp && NetworkCli.IsArpEnabled(args) &&
                !NetworkCli.IsArpEnabled(new[] { "--arp", "--no-arp" }) &&
                NetworkCli.IsArpEnabled(new[] { "--linux-password", "--no-arp" });
        });
        test("Linux neighbor parsing accepts complete static entries and rejects incomplete or invalid MACs", () =>
        {
            var neighbors = NeighborCacheReader.ParseLinuxLines(new[]
            {
                "IP address HW type Flags HW address Mask Device",
                "192.168.80.1 0x1 0x6 00:11:22:33:44:55 * eth0",
                "192.168.80.2 0x1 0x0 00:11:22:33:44:66 * eth0",
                "192.168.80.3 0x1 0x2 01:11:22:33:44:66 * eth0",
                "192.168.80.4 0x1 0x2 00:00:00:00:00:00 * eth0"
            });
            return neighbors.Count == 1 && neighbors["192.168.80.1"] == "00:11:22:33:44:55";
        });
        test("ARP cancellation propagates and never starts an automatic file scan", () =>
        {
            using var cancellation = new CancellationTokenSource();
            cancellation.CancelAfter(20);
            var arp = new FakeArpHostProbe(delayMilliseconds: 1000);
            try { _ = Inventory(arp, cancellationToken: cancellation.Token); return false; }
            catch (OperationCanceledException) { return !NetworkFileDiscovery.CanStart(0, true, null); }
        });
        test("ARP shares the configured host concurrency limit", () =>
        {
            var arp = new FakeArpHostProbe(delayMilliseconds: 10);
            _ = Inventory(arp, scopes: new[] { Scope("192.168.80.0/29") }, policy: Policy() with { MaxConcurrency = 2 });
            return arp.Calls.Count == 6 && arp.PeakConcurrency is > 0 and <= 2;
        });
        test("proxy-like ARP results are flagged and do not imply SMB or SSH access", () =>
        {
            var replies = Enumerable.Range(1, 14).ToDictionary(x => $"192.168.80.{x}",
                x => new ArpProbeObservation("02:AA:BB:CC:DD:EE", "fixture-lan", "192.168.80.100"));
            NetworkInventoryManifest inventory = Inventory(new FakeArpHostProbe(replies), scopes: new[] { Scope("192.168.80.0/28") });
            return inventory.Summary.ArpResolvedHosts == 14 && inventory.Warnings.Any(x => x.Contains("proxy ARP", StringComparison.Ordinal)) &&
                !NetworkFileDiscovery.SelectTargets(inventory, true, true, 22).HasTargets;
        });
        test("ARP evidence survives JSON and CSV output and cannot start file discovery without a service", () =>
        {
            var arp = new FakeArpHostProbe(new Dictionary<string, ArpProbeObservation>
            { ["192.168.80.1"] = new("02:AA:BB:CC:DD:EE", "fixture-lan", "192.168.80.10") });
            NetworkInventoryManifest inventory = Inventory(arp);
            string json = Path.Combine(root, "arp-inventory.json"), csv = Path.Combine(root, "arp-inventory.csv");
            NetworkInventoryStore.Write(json, csv, Path.Combine(root, "arp-targets"), inventory, true);
            NetworkInventoryManifest loaded = JsonSerializer.Deserialize<NetworkInventoryManifest>(File.ReadAllText(json), ManifestWriter.Options)!;
            return loaded.Hosts.Single().ArpResolved && loaded.Hosts.Single().ArpInterfaceName == "fixture-lan" &&
                File.ReadAllText(csv).Contains("arpResolved,arpInterfaceName", StringComparison.Ordinal) &&
                File.ReadAllText(csv).Contains("fixture-lan", StringComparison.Ordinal) &&
                !NetworkFileDiscovery.SelectTargets(loaded, true, true, 22).HasTargets;
        });

        static NetworkDiscoveryScope Scope(string cidr) => new(cidr, "ExplicitCidr", null, null,
            (long)Ipv4Cidr.Parse(cidr).UsableAddressCount, true);
        static NetworkDiscoveryPolicy Policy() => new(false, false, true, Array.Empty<int>(), 200, 2, 32, 1000,
            new ResourcePolicy(100, 0, 0, 64, 0));
        static NetworkInventoryManifest Inventory(FakeArpHostProbe arp, Func<IReadOnlyDictionary<string, string>>? cache = null,
            IReadOnlyList<NetworkDiscoveryScope>? scopes = null, IReadOnlyList<Ipv4Cidr>? exclusions = null,
            NetworkDiscoveryPolicy? policy = null, CancellationToken cancellationToken = default) =>
            new NetworkDiscoveryService(new FakeNetworkHostProbe(new Dictionary<string, NetworkProbeObservation>()),
                    cache ?? (() => new Dictionary<string, string>()), arp)
                .DiscoverAsync(scopes ?? new[] { Scope("192.168.80.0/30") }, exclusions ?? Array.Empty<Ipv4Cidr>(),
                    policy ?? Policy(), cancellationToken: cancellationToken).GetAwaiter().GetResult();
    }

    private sealed class FakeArpHostProbe : IArpHostProbe
    {
        private readonly IReadOnlyDictionary<string, ArpProbeObservation> _observations;
        private readonly int _delay;
        private int _active, _peak;
        public ConcurrentDictionary<string, int> Calls { get; } = new();
        public int PeakConcurrency => _peak;
        public IReadOnlyList<string> Warnings => Array.Empty<string>();
        public FakeArpHostProbe(IReadOnlyDictionary<string, ArpProbeObservation>? observations = null, int delayMilliseconds = 0)
        { _observations = observations ?? new Dictionary<string, ArpProbeObservation>(); _delay = delayMilliseconds; }
        public async Task<ArpProbeObservation?> ProbeAsync(IPAddress address, int timeoutMilliseconds, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls.AddOrUpdate(address.ToString(), 1, (_, count) => count + 1);
            int active = Interlocked.Increment(ref _active);
            int previous;
            do { previous = Volatile.Read(ref _peak); if (active <= previous) break; }
            while (Interlocked.CompareExchange(ref _peak, active, previous) != previous);
            try
            {
                if (_delay > 0) await Task.Delay(_delay, cancellationToken).ConfigureAwait(false);
                return _observations.TryGetValue(address.ToString(), out ArpProbeObservation? result) ? result : null;
            }
            finally { Interlocked.Decrement(ref _active); }
        }
    }
}
