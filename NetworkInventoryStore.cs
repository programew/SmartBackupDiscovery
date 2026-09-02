using System.Net;
using System.Text;
using System.Text.Json;

namespace SmartBackupDiscovery;

public sealed record NetworkInventoryArtifacts(
    string JsonPath,
    string CsvPath,
    string? WindowsHostsPath,
    string? LinuxHostsPath,
    string? ReviewHostsPath,
    string? SuggestedScopesPath);

public sealed record PreviousNetworkInventoryResult(NetworkInventoryManifest Manifest, string ReferencePath);

public static class NetworkInventoryStore
{
    public static NetworkInventoryManifest Read(string path)
    {
        string full = Path.GetFullPath(path);
        using var stream = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan);
        return JsonSerializer.Deserialize<NetworkInventoryManifest>(stream, ManifestWriter.Options)
               ?? throw new InvalidDataException($"Network inventory is empty or invalid: {full}");
    }

    public static NetworkInventoryArtifacts Write(
        string jsonPath,
        string csvPath,
        string targetsDirectory,
        NetworkInventoryManifest manifest,
        bool writeTargetLists)
    {
        jsonPath = Path.GetFullPath(jsonPath);
        csvPath = Path.GetFullPath(csvPath);
        if (jsonPath.Equals(csvPath, PathRules.Comparison))
            throw new ArgumentException("Network JSON and CSV output paths must be different.");

        WriteJsonOnly(jsonPath, manifest);
        AtomicWriteText(csvPath, BuildCsv(manifest.Hosts));

        string? windowsPath = null;
        string? linuxPath = null;
        string? reviewPath = null;
        string? suggestedScopesPath = null;
        if (writeTargetLists)
        {
            string directory = Path.GetFullPath(targetsDirectory);
            ManifestWriter.EnsureNoReparseAncestors(directory);
            Directory.CreateDirectory(directory);
            ManifestWriter.EnsureNoReparseAncestors(directory);

            windowsPath = Path.Combine(directory, "windows-smb-hosts.generated.txt");
            linuxPath = Path.Combine(directory, "linux-sftp-hosts.generated.txt");
            reviewPath = Path.Combine(directory, "unclassified-hosts.generated.txt");
            suggestedScopesPath = Path.Combine(directory, "suggested-private-scopes.generated.txt");
            AtomicWriteText(windowsPath, BuildWindowsTargets(manifest.Hosts));
            AtomicWriteText(linuxPath, BuildLinuxTargets(manifest.Hosts));
            AtomicWriteText(reviewPath, BuildReviewTargets(manifest.Hosts));
            AtomicWriteText(suggestedScopesPath, BuildSuggestedScopes(manifest.SuggestedScopes));
        }

        return new NetworkInventoryArtifacts(jsonPath, csvPath, windowsPath, linuxPath, reviewPath, suggestedScopesPath);
    }

    public static void WriteJsonOnly(string path, NetworkInventoryManifest manifest)
    {
        string full = Path.GetFullPath(path);
        string parent = Path.GetDirectoryName(full) ?? Environment.CurrentDirectory;
        ManifestWriter.EnsureNoReparseAncestors(parent);
        Directory.CreateDirectory(parent);
        ManifestWriter.EnsureNoReparseAncestors(parent);
        EnsureNotReparseFile(full);

        string staged = Path.Combine(parent, $".sbd-network-{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(staged, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024,
                       FileOptions.SequentialScan | FileOptions.WriteThrough))
            {
                JsonSerializer.Serialize(stream, manifest, ManifestWriter.Options);
                stream.Flush(flushToDisk: true);
            }
            File.Move(staged, full, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(staged)) File.Delete(staged); } catch { }
        }
    }

    private static string BuildCsv(IReadOnlyList<NetworkDiscoveredHost> hosts)
    {
        var output = new StringBuilder();
        output.AppendLine("ipAddress,hostName,macAddress,reachability,icmpReachable,roundtripMs,openTcpPorts,platformHint,recommendedTransport,scopeCidrs,evidence,lastSeenUtc");
        foreach (NetworkDiscoveredHost host in hosts)
        {
            string[] values =
            {
                host.IpAddress,
                host.HostName ?? string.Empty,
                host.MacAddress ?? string.Empty,
                host.Reachability,
                host.IcmpReachable ? "true" : "false",
                host.RoundtripTimeMilliseconds?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty,
                string.Join(";", host.OpenTcpPorts),
                host.PlatformHint,
                host.RecommendedTransport,
                string.Join(";", host.ScopeCidrs),
                string.Join(" | ", host.Evidence),
                host.LastSeenUtc.ToString("O", System.Globalization.CultureInfo.InvariantCulture)
            };
            output.AppendLine(string.Join(",", values.Select(EscapeCsv)));
        }
        return output.ToString();
    }

    private static string BuildWindowsTargets(IReadOnlyList<NetworkDiscoveredHost> hosts)
    {
        var output = new StringBuilder();
        output.AppendLine("# Generated network inventory candidates. Review before use.");
        output.AppendLine("# No share is assumed. Supply --remote-share <name> or add |Share to each reviewed host.");
        foreach (NetworkDiscoveredHost host in hosts.Where(x => x.PlatformHint is "WindowsOrSmb" or "MixedServices"))
        {
            if (!string.IsNullOrWhiteSpace(host.HostName)) output.AppendLine($"# {host.HostName}");
            output.AppendLine(host.IpAddress);
        }
        return output.ToString();
    }

    private static string BuildLinuxTargets(IReadOnlyList<NetworkDiscoveredHost> hosts)
    {
        var output = new StringBuilder();
        output.AppendLine("# Generated network inventory candidates. Review before use.");
        output.AppendLine("# Add explicit roots/fingerprint as HOST|/root1;/root2|SHA256_FINGERPRINT when known.");
        foreach (NetworkDiscoveredHost host in hosts.Where(x => x.PlatformHint is "LinuxOrSsh" or "MixedServices"))
        {
            if (!string.IsNullOrWhiteSpace(host.HostName)) output.AppendLine($"# {host.HostName}");
            output.AppendLine(host.IpAddress);
        }
        return output.ToString();
    }

    private static string BuildReviewTargets(IReadOnlyList<NetworkDiscoveredHost> hosts)
    {
        var output = new StringBuilder();
        output.AppendLine("# Responsive or neighbor-cached hosts without a conclusive SMB/SSH service hint.");
        foreach (NetworkDiscoveredHost host in hosts.Where(x => x.PlatformHint == "Unknown"))
            output.AppendLine($"{host.IpAddress}|{host.HostName ?? string.Empty}|{host.Reachability}|{string.Join(",", host.OpenTcpPorts)}");
        return output.ToString();
    }

    private static string BuildSuggestedScopes(IReadOnlyList<NetworkScopeSuggestion> scopes)
    {
        var output = new StringBuilder();
        output.AppendLine("# Passive/private scope hints only. No host in these ranges was actively probed by this suggestion step.");
        output.AppendLine("# Review routing and authorization before adding a scope with --cidr <CIDR> --authorized-scope.");
        foreach (NetworkScopeSuggestion scope in scopes)
        {
            output.AppendLine($"# {scope.Source}: {scope.Reason}");
            foreach (string evidence in scope.Evidence) output.AppendLine("#   " + evidence);
            output.AppendLine(scope.Cidr);
        }
        return output.ToString();
    }

    private static string EscapeCsv(string value)
    {
        if (value.IndexOfAny(new[] { ',', '"', '\r', '\n' }) < 0) return value;
        return '"' + value.Replace("\"", "\"\"") + '"';
    }

    private static void AtomicWriteText(string path, string contents)
    {
        string full = Path.GetFullPath(path);
        string parent = Path.GetDirectoryName(full) ?? Environment.CurrentDirectory;
        ManifestWriter.EnsureNoReparseAncestors(parent);
        Directory.CreateDirectory(parent);
        ManifestWriter.EnsureNoReparseAncestors(parent);
        EnsureNotReparseFile(full);

        string staged = Path.Combine(parent, $".sbd-output-{Guid.NewGuid():N}.tmp");
        try
        {
            File.WriteAllText(staged, contents, new UTF8Encoding(false));
            File.Move(staged, full, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(staged)) File.Delete(staged); } catch { }
        }
    }

    private static void EnsureNotReparseFile(string path)
    {
        if (File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException($"Refusing to overwrite reparse-point output file: {path}");
    }
}

public static class NetworkInventoryDiff
{
    public static NetworkInventoryDiffSummary Compare(
        NetworkInventoryManifest previous,
        NetworkInventoryManifest current,
        string? previousReference = null)
    {
        var before = previous.Hosts.ToDictionary(x => x.IpAddress, StringComparer.OrdinalIgnoreCase);
        var after = current.Hosts.ToDictionary(x => x.IpAddress, StringComparer.OrdinalIgnoreCase);
        var changes = new List<NetworkHostChange>();

        foreach (NetworkDiscoveredHost host in after.Values)
        {
            if (!before.TryGetValue(host.IpAddress, out NetworkDiscoveredHost? old))
            {
                changes.Add(Change("Added", null, host));
                continue;
            }
            if (!Equivalent(old, host)) changes.Add(Change("Changed", old, host));
        }
        foreach (NetworkDiscoveredHost host in before.Values)
            if (!after.ContainsKey(host.IpAddress)) changes.Add(Change("Removed", host, null));

        NetworkHostChange[] ordered = changes
            .OrderBy(x => ChangeOrder(x.ChangeType))
            .ThenBy(x => Ipv4Cidr.ToUInt32(IPAddress.Parse(x.IpAddress)))
            .ToArray();
        return new NetworkInventoryDiffSummary(
            true,
            previous.GeneratedAtUtc,
            previousReference,
            ordered.Count(x => x.ChangeType == "Added"),
            ordered.Count(x => x.ChangeType == "Removed"),
            ordered.Count(x => x.ChangeType == "Changed"),
            ordered);
    }

    private static bool Equivalent(NetworkDiscoveredHost left, NetworkDiscoveredHost right) =>
        string.Equals(left.HostName, right.HostName, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.MacAddress, right.MacAddress, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.Reachability, right.Reachability, StringComparison.Ordinal) &&
        string.Equals(left.PlatformHint, right.PlatformHint, StringComparison.Ordinal) &&
        left.OpenTcpPorts.OrderBy(x => x).SequenceEqual(right.OpenTcpPorts.OrderBy(x => x));

    private static NetworkHostChange Change(string type, NetworkDiscoveredHost? previous, NetworkDiscoveredHost? current) => new(
        type,
        current?.IpAddress ?? previous!.IpAddress,
        previous?.HostName,
        current?.HostName,
        previous?.PlatformHint,
        current?.PlatformHint,
        previous?.OpenTcpPorts ?? Array.Empty<int>(),
        current?.OpenTcpPorts ?? Array.Empty<int>());

    private static int ChangeOrder(string value) => value switch { "Added" => 0, "Changed" => 1, _ => 2 };
}

public static class NetworkInventoryHistoryService
{
    public static string GetDefaultHistoryDirectory(string inventoryPath)
    {
        string full = Path.GetFullPath(inventoryPath);
        string parent = Path.GetDirectoryName(full) ?? Environment.CurrentDirectory;
        string stem = Path.GetFileNameWithoutExtension(full);
        return Path.Combine(parent, ".sbd-network-history", stem);
    }

    public static PreviousNetworkInventoryResult? FindPrevious(
        string inventoryPath,
        string historyDirectory,
        NetworkInventoryManifest current)
    {
        string full = Path.GetFullPath(inventoryPath);
        if (File.Exists(full))
        {
            try
            {
                NetworkInventoryManifest existing = NetworkInventoryStore.Read(full);
                if (Comparable(existing, current)) return new PreviousNetworkInventoryResult(existing, full);
            }
            catch { }
        }

        string history = Path.GetFullPath(historyDirectory);
        if (!Directory.Exists(history)) return null;
        foreach (string file in Directory.EnumerateFiles(history, "sbd-network-*.json", SearchOption.TopDirectoryOnly)
                     .OrderByDescending(File.GetLastWriteTimeUtc))
        {
            try
            {
                NetworkInventoryManifest candidate = NetworkInventoryStore.Read(file);
                if (Comparable(candidate, current)) return new PreviousNetworkInventoryResult(candidate, file);
            }
            catch { }
        }
        return null;
    }

    public static string SaveSnapshot(string historyDirectory, NetworkInventoryManifest manifest)
    {
        string directory = Path.GetFullPath(historyDirectory);
        ManifestWriter.EnsureNoReparseAncestors(directory);
        Directory.CreateDirectory(directory);
        ManifestWriter.EnsureNoReparseAncestors(directory);
        string path = Path.Combine(directory, $"sbd-network-{manifest.GeneratedAtUtc:yyyyMMdd-HHmmssfff}Z-{Guid.NewGuid():N}.json");
        NetworkInventoryStore.WriteJsonOnly(path, manifest);
        return path;
    }

    public static int PruneSnapshots(string historyDirectory, int retainCount)
    {
        if (retainCount <= 0) return 0;
        string directory = Path.GetFullPath(historyDirectory);
        if (!Directory.Exists(directory)) return 0;
        ManifestWriter.EnsureNoReparseAncestors(directory);
        int removed = 0;
        foreach (string file in Directory.EnumerateFiles(directory, "sbd-network-*.json", SearchOption.TopDirectoryOnly)
                     .OrderByDescending(File.GetLastWriteTimeUtc)
                     .Skip(retainCount))
        {
            try
            {
                if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0) continue;
                File.Delete(file);
                removed++;
            }
            catch { }
        }
        return removed;
    }

    private static bool Comparable(NetworkInventoryManifest left, NetworkInventoryManifest right) =>
        left.Scopes.Select(x => x.Cidr).OrderBy(x => x, StringComparer.Ordinal)
            .SequenceEqual(right.Scopes.Select(x => x.Cidr).OrderBy(x => x, StringComparer.Ordinal), StringComparer.Ordinal) &&
        left.ExcludedCidrs.OrderBy(x => x, StringComparer.Ordinal)
            .SequenceEqual(right.ExcludedCidrs.OrderBy(x => x, StringComparer.Ordinal), StringComparer.Ordinal);
}
