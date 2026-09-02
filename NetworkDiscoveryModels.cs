namespace SmartBackupDiscovery;

public sealed record NetworkDiscoveryScope(
    string Cidr,
    string Source,
    string? InterfaceName,
    string? LocalAddress,
    long CandidateAddresses,
    bool ExplicitlyAuthorized);

public sealed record NetworkDiscoveryPolicy(
    bool UseIcmp,
    bool ResolveDns,
    bool ReadNeighborCache,
    IReadOnlyList<int> TcpPorts,
    int ProbeTimeoutMilliseconds,
    int MaxConcurrency,
    int MaxHosts,
    double MaxProbesPerSecond,
    ResourcePolicy ResourcePolicy);

public sealed record NetworkDiscoveryProgress(
    int HostsCompleted,
    int HostsTotal,
    int HostsFound,
    string CurrentAddress);

public sealed record NetworkScopeSuggestion(
    string Cidr,
    string Source,
    string Reason,
    IReadOnlyList<string> Evidence,
    bool ActivelyProbed);

public sealed record NetworkDiscoveredHost(
    string IpAddress,
    string? HostName,
    string? MacAddress,
    string Reachability,
    bool IcmpReachable,
    long? RoundtripTimeMilliseconds,
    IReadOnlyList<int> OpenTcpPorts,
    string PlatformHint,
    string RecommendedTransport,
    IReadOnlyList<string> ScopeCidrs,
    IReadOnlyList<string> Evidence,
    DateTime LastSeenUtc);

public sealed record NetworkInventorySummary(
    int AddressesConsidered,
    int HostsFound,
    int WindowsOrSmbHosts,
    int LinuxOrSshHosts,
    int MixedServiceHosts,
    int UnknownHosts,
    int NeighborCacheOnlyHosts);

public sealed record NetworkHostChange(
    string ChangeType,
    string IpAddress,
    string? PreviousHostName,
    string? CurrentHostName,
    string? PreviousPlatformHint,
    string? CurrentPlatformHint,
    IReadOnlyList<int> PreviousOpenTcpPorts,
    IReadOnlyList<int> CurrentOpenTcpPorts);

public sealed record NetworkInventoryDiffSummary(
    bool PreviousInventoryAvailable,
    DateTime? PreviousGeneratedAtUtc,
    string? PreviousInventoryReference,
    int AddedCount,
    int RemovedCount,
    int ChangedCount,
    IReadOnlyList<NetworkHostChange> Changes)
{
    public static NetworkInventoryDiffSummary NoPrevious() => new(
        false, null, null, 0, 0, 0, Array.Empty<NetworkHostChange>());
}

public sealed class NetworkInventoryManifest
{
    public string FormatVersion { get; init; } = "1.0";
    public string ApplicationVersion { get; init; } = "3.4.0";
    public DateTime GeneratedAtUtc { get; init; } = DateTime.UtcNow;
    public HostIdentity ScannerHost { get; init; } = SourceIdentityProvider.GetScannerHostIdentity();
    public IReadOnlyList<NetworkDiscoveryScope> Scopes { get; init; } = Array.Empty<NetworkDiscoveryScope>();
    public IReadOnlyList<string> ExcludedCidrs { get; init; } = Array.Empty<string>();
    public NetworkDiscoveryPolicy Policy { get; init; } = NetworkDiscoveryDefaults.Policy;
    public IReadOnlyList<NetworkDiscoveredHost> Hosts { get; init; } = Array.Empty<NetworkDiscoveredHost>();
    public IReadOnlyList<NetworkScopeSuggestion> SuggestedScopes { get; init; } = Array.Empty<NetworkScopeSuggestion>();
    public NetworkInventorySummary Summary { get; init; } = new(0, 0, 0, 0, 0, 0, 0);
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Errors { get; init; } = Array.Empty<string>();
    public NetworkInventoryDiffSummary Diff { get; set; } = NetworkInventoryDiffSummary.NoPrevious();
}

public static class NetworkDiscoveryDefaults
{
    public static NetworkDiscoveryPolicy Policy { get; } = new(
        UseIcmp: true,
        ResolveDns: true,
        ReadNeighborCache: true,
        TcpPorts: new[] { 22, 445 },
        ProbeTimeoutMilliseconds: 600,
        MaxConcurrency: 32,
        MaxHosts: 4096,
        MaxProbesPerSecond: 64,
        ResourcePolicy: ResourcePolicy.Default);
}

public sealed record NetworkProbeObservation(
    bool IcmpReachable,
    long? RoundtripTimeMilliseconds,
    IReadOnlyList<int> OpenTcpPorts,
    string? HostName);

public interface INetworkHostProbe
{
    Task<NetworkProbeObservation> ProbeAsync(
        System.Net.IPAddress address,
        NetworkDiscoveryPolicy policy,
        CancellationToken cancellationToken);
}
