using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;

namespace SmartBackupDiscovery;

public sealed class NetworkDiscoveryService
{
    private readonly INetworkHostProbe _probe;
    private readonly Func<IReadOnlyDictionary<string, string>> _neighborCacheReader;
    private readonly IArpHostProbe _arpProbe;

    public NetworkDiscoveryService(
        INetworkHostProbe? probe = null,
        Func<IReadOnlyDictionary<string, string>>? neighborCacheReader = null,
        IArpHostProbe? arpProbe = null)
    {
        _probe = probe ?? new SystemNetworkHostProbe();
        _neighborCacheReader = neighborCacheReader ?? NeighborCacheReader.ReadIpv4;
        _arpProbe = arpProbe ?? new SystemArpHostProbe();
    }

    public async Task<NetworkInventoryManifest> DiscoverAsync(
        IReadOnlyList<NetworkDiscoveryScope> scopes,
        IReadOnlyList<Ipv4Cidr> excludedScopes,
        NetworkDiscoveryPolicy policy,
        IReadOnlyList<string>? initialWarnings = null,
        Action<NetworkDiscoveryProgress>? progress = null,
        CancellationToken cancellationToken = default,
        IReadOnlyList<NetworkScopeSuggestion>? initialScopeSuggestions = null)
    {
        ValidatePolicy(policy);
        Dictionary<uint, HashSet<string>> targets = ExpandTargets(scopes, excludedScopes, policy.MaxHosts);
        var neighborCache = policy.ReadNeighborCache
            ? _neighborCacheReader()
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var localAddresses = scopes
            .Select(x => x.LocalAddress)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var discovered = new ConcurrentBag<NetworkDiscoveredHost>();
        var errors = new ConcurrentQueue<string>();
        var warnings = new ConcurrentQueue<string>(initialWarnings ?? Array.Empty<string>());
        var rateGate = new AsyncProbeRateGate(policy.MaxProbesPerSecond);
        var governor = new ResourceGovernor(policy.ResourcePolicy);
        var governorGate = new object();
        var progressGate = new object();
        int completed = 0;
        int found = 0;

        var work = targets
            .OrderBy(x => x.Key)
            .Select(x => new NetworkProbeTarget(Ipv4Cidr.FromUInt32(x.Key), x.Value.OrderBy(v => v, StringComparer.Ordinal).ToArray()))
            .ToArray();

        await Parallel.ForEachAsync(
            work,
            new ParallelOptions { MaxDegreeOfParallelism = policy.MaxConcurrency, CancellationToken = cancellationToken },
            async (target, token) =>
            {
                await rateGate.WaitAsync(token).ConfigureAwait(false);
                lock (governorGate)
                {
                    governor.BeforeWork(remote: true);
                    governor.AccountNetworkBytes(EstimateProbeBytes(policy), null);
                }

                Task<ArpProbeObservation?> arpTask = policy.UseArp
                    ? ProbeArpAsync(target.Address, policy, warnings, token)
                    : Task.FromResult<ArpProbeObservation?>(null);
                NetworkProbeObservation observation;
                try
                {
                    observation = await _probe.ProbeAsync(target.Address, policy, token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    errors.Enqueue($"Probe failed for {target.Address}: {ex.Message}");
                    observation = new NetworkProbeObservation(false, null, Array.Empty<int>(), null);
                }

                ArpProbeObservation? arp = await arpTask.ConfigureAwait(false);
                if (arp is not null && policy.ResolveDns && string.IsNullOrWhiteSpace(observation.HostName))
                    observation = observation with { HostName = await SystemNetworkHostProbe.TryResolveHostNameAsync(
                        target.Address, policy.ProbeTimeoutMilliseconds, token).ConfigureAwait(false) };

                string ip = target.Address.ToString();
                bool neighborKnown = neighborCache.TryGetValue(ip, out string? macAddress);
                bool isScannerAddress = localAddresses.Contains(ip);
                bool responsive = observation.IcmpReachable || observation.OpenTcpPorts.Count > 0;
                if (responsive || arp is not null || neighborKnown || isScannerAddress)
                {
                    IReadOnlyList<int> ports = observation.OpenTcpPorts.Distinct().OrderBy(x => x).ToArray();
                    (string platform, string transport) = Classify(ports);
                    var evidence = new List<string>();
                    if (observation.IcmpReachable) evidence.Add("ICMP echo response");
                    if (ports.Count > 0) evidence.Add("Open TCP ports: " + string.Join(",", ports));
                    if (arp is not null) evidence.Add($"Fresh ARP resolution on {arp.InterfaceName} from {arp.LocalAddress}; a proxy may answer for an IP");
                    if (neighborKnown) evidence.Add("Present in the scanner host's IPv4 neighbor cache");
                    if (isScannerAddress) evidence.Add("Address belongs to the scanner host");

                    string reachability = responsive
                        ? "Reachable"
                        : arp is not null ? "ArpResolved"
                        : isScannerAddress
                            ? "ScannerAddress"
                            : "NeighborCacheOnly";
                    string? hostName = observation.HostName;
                    if (isScannerAddress && string.IsNullOrWhiteSpace(hostName)) hostName = Environment.MachineName;

                    discovered.Add(new NetworkDiscoveredHost(
                        ip,
                        hostName,
                        arp?.MacAddress ?? (neighborKnown ? macAddress : null),
                        reachability,
                        observation.IcmpReachable,
                        observation.RoundtripTimeMilliseconds,
                        ports,
                        platform,
                        transport,
                        target.ScopeCidrs,
                        evidence,
                        DateTime.UtcNow)
                    {
                        ArpResolved = arp is not null,
                        ArpInterfaceName = arp?.InterfaceName
                    });
                    Interlocked.Increment(ref found);
                }

                int currentCompleted = Interlocked.Increment(ref completed);
                if (progress is not null)
                {
                    lock (progressGate)
                        progress(new NetworkDiscoveryProgress(currentCompleted, work.Length, Volatile.Read(ref found), ip));
                }
            }).ConfigureAwait(false);

        // ICMP/TCP and active ARP can populate the kernel cache during a scan.
        // Refresh it once, retaining cached-only status when no fresh reply was
        // observed by the ARP resolver or the IP/service probes.
        var finalNeighbors = new Dictionary<string, string>(neighborCache, StringComparer.OrdinalIgnoreCase);
        if (policy.ReadNeighborCache)
            foreach (var entry in _neighborCacheReader()) finalNeighbors[entry.Key] = entry.Value;
        var known = discovered.Select(x => x.IpAddress).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (NetworkProbeTarget target in work)
        {
            string ip = target.Address.ToString();
            if (!known.Contains(ip) && finalNeighbors.TryGetValue(ip, out string? mac))
                discovered.Add(new NetworkDiscoveredHost(ip, null, mac, "NeighborCacheOnly", false, null,
                    Array.Empty<int>(), "Unknown", "Manual review required", target.ScopeCidrs,
                    new[] { "Present in the scanner host's refreshed IPv4 neighbor cache; not confirmed by an active response" }, DateTime.UtcNow));
        }
        NetworkDiscoveredHost[] hosts = discovered
            .Select(x => !x.ArpResolved && finalNeighbors.TryGetValue(x.IpAddress, out string? mac) ? x with { MacAddress = mac } : x)
            .OrderBy(x => Ipv4Cidr.ToUInt32(IPAddress.Parse(x.IpAddress)))
            .ToArray();
        if (policy.UseArp)
            foreach (string warning in _arpProbe.Warnings) warnings.Enqueue(warning);
        foreach (var group in hosts.Where(x => x.ArpResolved && !x.IcmpReachable && x.OpenTcpPorts.Count == 0)
                     .GroupBy(x => $"{x.ArpInterfaceName}|{x.MacAddress}", StringComparer.OrdinalIgnoreCase).Where(x => x.Count() >= 8))
            warnings.Enqueue($"{group.Count()} ARP-only addresses resolved to the same MAC on one interface; proxy ARP or address aliases may be present. These are not confirmed separate devices.");
        progress?.Invoke(new NetworkDiscoveryProgress(work.Length, work.Length, hosts.Length, string.Empty));
        NetworkInventorySummary summary = BuildSummary(work.Length, hosts);
        IReadOnlyList<NetworkScopeSuggestion> scopeSuggestions = BuildScopeSuggestions(
            finalNeighbors.Keys,
            scopes,
            excludedScopes,
            initialScopeSuggestions);

        return new NetworkInventoryManifest
        {
            Scopes = scopes,
            ExcludedCidrs = excludedScopes.Select(x => x.Canonical).OrderBy(x => x, StringComparer.Ordinal).ToArray(),
            Policy = policy,
            Hosts = hosts,
            SuggestedScopes = scopeSuggestions,
            Summary = summary,
            Warnings = warnings.Distinct(StringComparer.Ordinal).ToArray(),
            Errors = errors.ToArray()
        };
    }

    private async Task<ArpProbeObservation?> ProbeArpAsync(IPAddress address, NetworkDiscoveryPolicy policy,
        ConcurrentQueue<string> warnings, CancellationToken cancellationToken)
    {
        try { return await _arpProbe.ProbeAsync(address, policy.ProbeTimeoutMilliseconds, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            warnings.Enqueue("Active ARP warning: " + ex.Message);
            return null;
        }
    }

    internal static Dictionary<uint, HashSet<string>> ExpandTargets(
        IReadOnlyList<NetworkDiscoveryScope> scopes,
        IReadOnlyList<Ipv4Cidr> exclusions,
        int maxHosts)
    {
        var result = new Dictionary<uint, HashSet<string>>();
        foreach (NetworkDiscoveryScope scope in scopes)
        {
            Ipv4Cidr cidr = Ipv4Cidr.Parse(scope.Cidr);
            foreach (IPAddress address in cidr.EnumerateUsableAddresses())
            {
                uint value = Ipv4Cidr.ToUInt32(address);
                if (exclusions.Any(x => x.Contains(value))) continue;
                if (!result.TryGetValue(value, out HashSet<string>? memberships))
                {
                    if (result.Count >= maxHosts)
                        throw new InvalidOperationException(
                            $"Authorized scope contains more than the configured {maxHosts:N0} address limit. Narrow --cidr/--exclude-cidr or deliberately raise --max-hosts (hard limit 65,536).");
                    memberships = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    result[value] = memberships;
                }
                memberships.Add(cidr.Canonical);
            }
        }

        if (result.Count == 0)
            throw new InvalidOperationException("The selected scopes contain no usable addresses after exclusions.");
        return result;
    }

    internal static (string PlatformHint, string RecommendedTransport) Classify(IReadOnlyList<int> openPorts)
    {
        bool windows = openPorts.Contains(445) || openPorts.Contains(139) || openPorts.Contains(3389) || openPorts.Contains(5985) || openPorts.Contains(5986);
        bool ssh = openPorts.Contains(22);
        if (windows && ssh) return ("MixedServices", "Review: SMB and SSH/SFTP detected");
        if (windows) return ("WindowsOrSmb", "SMB (explicit share required)");
        if (ssh) return ("LinuxOrSsh", "SSH/SFTP (host-key verification required)");
        return ("Unknown", "Manual review required");
    }

    private static NetworkInventorySummary BuildSummary(int considered, IReadOnlyList<NetworkDiscoveredHost> hosts) => new(
        considered,
        hosts.Count,
        hosts.Count(x => x.PlatformHint == "WindowsOrSmb"),
        hosts.Count(x => x.PlatformHint == "LinuxOrSsh"),
        hosts.Count(x => x.PlatformHint == "MixedServices"),
        hosts.Count(x => x.PlatformHint == "Unknown"),
        hosts.Count(x => x.Reachability == "NeighborCacheOnly"))
    { ArpResolvedHosts = hosts.Count(x => x.ArpResolved) };

    private static IReadOnlyList<NetworkScopeSuggestion> BuildScopeSuggestions(
        IEnumerable<string> neighborAddresses,
        IReadOnlyList<NetworkDiscoveryScope> selectedScopes,
        IReadOnlyList<Ipv4Cidr> excludedScopes,
        IReadOnlyList<NetworkScopeSuggestion>? initialSuggestions)
    {
        Ipv4Cidr[] active = selectedScopes.Select(x => Ipv4Cidr.Parse(x.Cidr)).ToArray();
        var neighborGroups = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (string raw in neighborAddresses)
        {
            if (!IPAddress.TryParse(raw, out IPAddress? address) || address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) continue;
            Ipv4Cidr host = Ipv4Cidr.FromAddress(address, 32);
            if (!host.IsPrivateScope() || active.Any(x => x.Contains(address)) || excludedScopes.Any(x => x.Contains(address))) continue;
            string candidate = Ipv4Cidr.FromAddress(address, 24).Canonical;
            if (!neighborGroups.TryGetValue(candidate, out List<string>? evidence))
            {
                evidence = new List<string>();
                neighborGroups[candidate] = evidence;
            }
            if (evidence.Count < 8) evidence.Add("out-of-scope neighbor=" + address);
        }

        var combined = new List<NetworkScopeSuggestion>();
        if (initialSuggestions is not null) combined.AddRange(initialSuggestions);
        combined.AddRange(neighborGroups.Select(group => new NetworkScopeSuggestion(
            group.Key,
            "OutOfScopeNeighborCache",
            "A private IPv4 neighbor outside the selected subnet was observed. This may indicate a secondary subnet on the same Layer-2 segment; /24 is only a conservative review starting point.",
            group.Value,
            false)));
        return combined
            .GroupBy(x => $"{x.Cidr}|{x.Source}", StringComparer.OrdinalIgnoreCase)
            .Select(x => x.First())
            .OrderBy(x => Ipv4Cidr.Parse(x.Cidr).NetworkValue)
            .ThenBy(x => x.Cidr, StringComparer.Ordinal)
            .ToArray();
    }

    private static void ValidatePolicy(NetworkDiscoveryPolicy policy)
    {
        if (!policy.UseIcmp && policy.TcpPorts.Count == 0 && !policy.ReadNeighborCache && !policy.UseArp)
            throw new ArgumentException("At least one discovery signal must be enabled: active ARP, ICMP, a TCP probe port, or neighbor-cache reading.");
        if (policy.ProbeTimeoutMilliseconds is < 100 or > 30_000)
            throw new ArgumentOutOfRangeException(nameof(policy.ProbeTimeoutMilliseconds));
        if (policy.MaxConcurrency is < 1 or > 256)
            throw new ArgumentOutOfRangeException(nameof(policy.MaxConcurrency));
        if (policy.MaxHosts is < 1 or > 65_536)
            throw new ArgumentOutOfRangeException(nameof(policy.MaxHosts));
        if (policy.MaxProbesPerSecond is < 1 or > 10_000)
            throw new ArgumentOutOfRangeException(nameof(policy.MaxProbesPerSecond));
        if (policy.TcpPorts.Count > 16 || policy.TcpPorts.Any(x => x is < 1 or > 65535))
            throw new ArgumentException("Supply at most 16 valid TCP probe ports.");
    }

    private static int EstimateProbeBytes(NetworkDiscoveryPolicy policy)
    {
        int probes = policy.TcpPorts.Count + (policy.UseIcmp ? 1 : 0);
        return Math.Max(128, probes * 256 + (policy.UseArp ? 168 : 0));
    }

    private sealed record NetworkProbeTarget(IPAddress Address, IReadOnlyList<string> ScopeCidrs);

    private sealed class AsyncProbeRateGate
    {
        private readonly long _intervalTicks;
        private readonly object _gate = new();
        private long _nextTimestamp;

        public AsyncProbeRateGate(double permitsPerSecond)
        {
            _intervalTicks = Math.Max(1, (long)Math.Ceiling(Stopwatch.Frequency / permitsPerSecond));
        }

        public async Task WaitAsync(CancellationToken cancellationToken)
        {
            long scheduled;
            long now;
            lock (_gate)
            {
                now = Stopwatch.GetTimestamp();
                scheduled = Math.Max(now, _nextTimestamp);
                _nextTimestamp = scheduled > long.MaxValue - _intervalTicks ? now : scheduled + _intervalTicks;
            }

            long remaining = scheduled - now;
            if (remaining <= 0) return;
            int delayMilliseconds = Math.Max(1, (int)Math.Ceiling(remaining * 1000.0 / Stopwatch.Frequency));
            await Task.Delay(delayMilliseconds, cancellationToken).ConfigureAwait(false);
        }
    }
}
