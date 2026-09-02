namespace SmartBackupDiscovery;

public static class NetworkCli
{
    public static int Run(string[] args)
    {
        var explicitCidrs = GetOptions(args, "--cidr");
        var rawExclusions = GetOptions(args, "--exclude-cidr");
        bool includeLocal = args.Contains("--include-local-scopes", StringComparer.OrdinalIgnoreCase);
        bool authorized = args.Contains("--authorized-scope", StringComparer.OrdinalIgnoreCase);
        var warnings = new List<string>();
        var scopeSuggestions = new List<NetworkScopeSuggestion>();
        IReadOnlyList<NetworkDiscoveryScope> scopes = NetworkScopePlanner.ResolveScopes(
            explicitCidrs,
            includeLocal,
            authorized,
            warnings,
            scopeSuggestions);
        IReadOnlyList<Ipv4Cidr> exclusions = NetworkScopePlanner.ParseExclusions(rawExclusions);

        var defaults = NetworkDiscoveryDefaults.Policy;
        bool noTcp = args.Contains("--no-tcp-probes", StringComparer.OrdinalIgnoreCase);
        List<int> requestedPorts = GetIntOptions(args, "--probe-port", 1, 65535);
        if (noTcp && requestedPorts.Count > 0)
            throw new ArgumentException("--no-tcp-probes cannot be combined with --probe-port.");
        IReadOnlyList<int> ports = noTcp
            ? Array.Empty<int>()
            : requestedPorts.Count > 0
                ? requestedPorts.Distinct().OrderBy(x => x).ToArray()
                : defaults.TcpPorts;

        int timeout = GetInt(args, "--probe-timeout-ms", defaults.ProbeTimeoutMilliseconds, 100, 30_000);
        int concurrency = GetInt(args, "--network-concurrency", defaults.MaxConcurrency, 1, 256);
        int maxHosts = GetInt(args, "--max-hosts", defaults.MaxHosts, 1, 65_536);
        double probeRate = GetDouble(args, "--max-probes-per-second", defaults.MaxProbesPerSecond, 1, 10_000);
        double maxCpu = GetDouble(args, "--max-cpu-percent", ResourcePolicy.Default.MaxCpuPercent, 1, 100);
        double networkMbps = GetDouble(args, "--network-limit-mbps", ResourcePolicy.Default.GlobalNetworkMbps, 0, 100_000);
        int maxAdaptiveDelay = GetInt(args, "--max-adaptive-delay-ms", ResourcePolicy.Default.MaxAdaptiveDelayMilliseconds, 0, 5000);
        var resourcePolicy = new ResourcePolicy(maxCpu, networkMbps, 0, ResourcePolicy.Default.IoBufferKiB, maxAdaptiveDelay);
        var policy = new NetworkDiscoveryPolicy(
            UseIcmp: !args.Contains("--no-icmp", StringComparer.OrdinalIgnoreCase),
            ResolveDns: !args.Contains("--no-dns", StringComparer.OrdinalIgnoreCase),
            ReadNeighborCache: !args.Contains("--no-neighbor-cache", StringComparer.OrdinalIgnoreCase),
            TcpPorts: ports,
            ProbeTimeoutMilliseconds: timeout,
            MaxConcurrency: concurrency,
            MaxHosts: maxHosts,
            MaxProbesPerSecond: probeRate,
            ResourcePolicy: resourcePolicy);

        string output = Path.GetFullPath(GetOption(args, "--output") ?? Path.Combine(Environment.CurrentDirectory, "network-inventory.json"));
        string csv = Path.GetFullPath(GetOption(args, "--csv") ?? Path.ChangeExtension(output, ".csv"));
        string outputParent = Path.GetDirectoryName(output) ?? Environment.CurrentDirectory;
        string targetsDirectory = Path.GetFullPath(GetOption(args, "--targets-dir") ?? Path.Combine(outputParent, "network-targets"));
        bool writeTargetLists = !args.Contains("--no-target-lists", StringComparer.OrdinalIgnoreCase);
        bool historyEnabled = !args.Contains("--no-network-history", StringComparer.OrdinalIgnoreCase);
        string historyDirectory = Path.GetFullPath(GetOption(args, "--network-history-dir") ?? NetworkInventoryHistoryService.GetDefaultHistoryDirectory(output));
        int historyRetain = GetInt(args, "--network-history-retain", 30, 0, 10_000);

        Console.WriteLine("SmartBackupDiscovery 3.4 - controlled automatic network inventory");
        Console.WriteLine("Boundary: private IPv4 inventory only; no authentication, share enumeration, file access, or automatic file scan.");
        foreach (NetworkDiscoveryScope scope in scopes)
            Console.WriteLine($"Scope: {scope.Cidr} [{scope.Source}] addresses={scope.CandidateAddresses:N0}{(scope.InterfaceName is null ? string.Empty : $" interface={scope.InterfaceName}")}");
        if (exclusions.Count > 0) Console.WriteLine("Excluded: " + string.Join(", ", exclusions.Select(x => x.Canonical)));
        Console.WriteLine($"Signals: ICMP={policy.UseIcmp}, DNS={policy.ResolveDns}, neighbor-cache={policy.ReadNeighborCache}, TCP=[{string.Join(",", policy.TcpPorts)}]");
        Console.WriteLine($"Limits: hosts={maxHosts:N0}, concurrency={concurrency}, probes/sec={probeRate:0.##}, timeout={timeout}ms, CPU<={maxCpu:0.#}%");

        bool progressLineOpen = false;
        DateTime lastRedirectedProgress = DateTime.MinValue;
        void ShowProgress(NetworkDiscoveryProgress value)
        {
            string line = $"Network inventory: {value.HostsCompleted:N0}/{value.HostsTotal:N0} addresses | {value.HostsFound:N0} hosts | {value.CurrentAddress}";
            if (Console.IsOutputRedirected)
            {
                if (value.HostsCompleted != value.HostsTotal &&
                    value.HostsCompleted % 100 != 0 &&
                    DateTime.UtcNow - lastRedirectedProgress < TimeSpan.FromSeconds(5)) return;
                lastRedirectedProgress = DateTime.UtcNow;
                Console.WriteLine(line);
                return;
            }

            int width;
            try { width = Math.Max(20, Console.WindowWidth - 1); } catch { width = 120; }
            if (line.Length > width) line = line[..Math.Max(1, width - 3)] + "...";
            Console.Write('\r' + line.PadRight(width));
            progressLineOpen = true;
        }

        using var cancellation = new CancellationTokenSource();
        ConsoleCancelEventHandler cancelHandler = (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancellation.Cancel();
        };
        Console.CancelKeyPress += cancelHandler;
        NetworkInventoryManifest inventory;
        try
        {
            inventory = new NetworkDiscoveryService()
                .DiscoverAsync(scopes, exclusions, policy, warnings, ShowProgress, cancellation.Token, scopeSuggestions)
                .GetAwaiter().GetResult();
        }
        finally
        {
            Console.CancelKeyPress -= cancelHandler;
            if (progressLineOpen) Console.WriteLine();
        }

        PreviousNetworkInventoryResult? previous = historyEnabled
            ? NetworkInventoryHistoryService.FindPrevious(output, historyDirectory, inventory)
            : null;
        inventory.Diff = previous is null
            ? NetworkInventoryDiffSummary.NoPrevious()
            : NetworkInventoryDiff.Compare(previous.Manifest, inventory, Path.GetFileName(previous.ReferencePath));

        NetworkInventoryArtifacts artifacts = NetworkInventoryStore.Write(output, csv, targetsDirectory, inventory, writeTargetLists);
        if (historyEnabled)
        {
            try
            {
                string snapshot = NetworkInventoryHistoryService.SaveSnapshot(historyDirectory, inventory);
                int removed = NetworkInventoryHistoryService.PruneSnapshots(historyDirectory, historyRetain);
                Console.WriteLine($"Network history snapshot: {snapshot}");
                if (removed > 0) Console.WriteLine($"Network history retention: removed {removed} old snapshot(s).");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Network history warning: " + ex.Message);
            }
        }

        PrintSummary(inventory, artifacts);
        return inventory.Errors.Count == 0 ? 0 : 1;
    }

    private static void PrintSummary(NetworkInventoryManifest inventory, NetworkInventoryArtifacts artifacts)
    {
        NetworkInventorySummary summary = inventory.Summary;
        Console.WriteLine($"Hosts found: {summary.HostsFound:N0} / {summary.AddressesConsidered:N0} addresses considered");
        Console.WriteLine($"  Windows/SMB: {summary.WindowsOrSmbHosts:N0} | Linux/SSH: {summary.LinuxOrSshHosts:N0} | mixed: {summary.MixedServiceHosts:N0} | unknown: {summary.UnknownHosts:N0}");
        Console.WriteLine($"  Neighbor-cache only (may be stale): {summary.NeighborCacheOnlyHosts:N0}");
        if (inventory.Diff.PreviousInventoryAvailable)
            Console.WriteLine($"Since previous comparable inventory: +{inventory.Diff.AddedCount:N0} added, ~{inventory.Diff.ChangedCount:N0} changed, -{inventory.Diff.RemovedCount:N0} removed");
        foreach (string warning in inventory.Warnings) Console.WriteLine("Warning: " + warning);
        foreach (NetworkScopeSuggestion suggestion in inventory.SuggestedScopes)
            Console.WriteLine($"Passive scope suggestion (not probed): {suggestion.Cidr} [{suggestion.Source}]");
        foreach (string error in inventory.Errors.Take(20)) Console.Error.WriteLine("Error: " + error);
        Console.WriteLine("Network inventory JSON: " + artifacts.JsonPath);
        Console.WriteLine("Network inventory CSV: " + artifacts.CsvPath);
        if (artifacts.WindowsHostsPath is not null) Console.WriteLine("Reviewed Windows target list: " + artifacts.WindowsHostsPath);
        if (artifacts.LinuxHostsPath is not null) Console.WriteLine("Reviewed Linux target list: " + artifacts.LinuxHostsPath);
        if (artifacts.ReviewHostsPath is not null) Console.WriteLine("Unclassified host list: " + artifacts.ReviewHostsPath);
        if (artifacts.SuggestedScopesPath is not null) Console.WriteLine("Suggested private scopes: " + artifacts.SuggestedScopesPath);
        Console.WriteLine("Discovery results are suggestions only. Review target lists before credentialed SMB/SFTP discovery.");
    }

    private static string? GetOption(string[] args, string name)
    {
        for (int i = 0; i < args.Length - 1; i++)
            if (args[i].Equals(name, StringComparison.OrdinalIgnoreCase)) return args[i + 1];
        return null;
    }

    private static List<string> GetOptions(string[] args, string name)
    {
        var result = new List<string>();
        for (int i = 0; i < args.Length - 1; i++)
            if (args[i].Equals(name, StringComparison.OrdinalIgnoreCase)) result.Add(args[i + 1]);
        return result;
    }

    private static List<int> GetIntOptions(string[] args, string name, int min, int max)
    {
        var result = new List<int>();
        foreach (string value in GetOptions(args, name))
        {
            if (!int.TryParse(value, out int parsed) || parsed < min || parsed > max)
                throw new ArgumentException($"{name} must be between {min} and {max}.");
            result.Add(parsed);
        }
        return result;
    }

    private static int GetInt(string[] args, string name, int fallback, int min, int max)
    {
        string? value = GetOption(args, name);
        if (value is null) return fallback;
        if (!int.TryParse(value, out int parsed) || parsed < min || parsed > max)
            throw new ArgumentException($"{name} must be between {min} and {max}.");
        return parsed;
    }

    private static double GetDouble(string[] args, string name, double fallback, double min, double max)
    {
        string? value = GetOption(args, name);
        if (value is null) return fallback;
        if (!double.TryParse(value, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out double parsed) || parsed < min || parsed > max)
            throw new ArgumentException($"{name} must be between {min} and {max}.");
        return parsed;
    }
}
