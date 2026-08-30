namespace SmartBackupDiscovery;

public sealed record PreviousManifestResult(DiscoveryManifest Manifest, string ReferencePath);

public static class ManifestHistoryService
{
    public static string GetDefaultHistoryDirectory(string manifestPath)
    {
        string full = Path.GetFullPath(manifestPath);
        string parent = Path.GetDirectoryName(full) ?? Environment.CurrentDirectory;
        string stem = Path.GetFileNameWithoutExtension(full);
        return Path.Combine(parent, ".sbd-history", stem);
    }

    public static PreviousManifestResult? FindPrevious(string manifestPath, string historyDirectory, DiscoveryManifest current)
    {
        string fullManifest = Path.GetFullPath(manifestPath);
        if (File.Exists(fullManifest))
        {
            try
            {
                DiscoveryManifest existing = ManifestReader.Read(fullManifest);
                if (IsComparable(existing, current))
                    return new PreviousManifestResult(existing, fullManifest);
            }
            catch
            {
                // Continue to snapshots; an invalid current file should not destroy history usability.
            }
        }

        string fullHistory = Path.GetFullPath(historyDirectory);
        if (!Directory.Exists(fullHistory)) return null;

        foreach (string file in Directory.EnumerateFiles(fullHistory, "*.json", SearchOption.TopDirectoryOnly)
                     .OrderByDescending(File.GetLastWriteTimeUtc))
        {
            try
            {
                DiscoveryManifest candidate = ManifestReader.Read(file);
                if (IsComparable(candidate, current))
                    return new PreviousManifestResult(candidate, file);
            }
            catch
            {
                // Skip corrupt/incompatible snapshots and continue to older ones.
            }
        }
        return null;
    }

    private static bool IsComparable(DiscoveryManifest previous, DiscoveryManifest current)
    {
        static string[] ScopeEntries(DiscoveryManifest m)
        {
            IEnumerable<string> scannedRoots = m.Sources.Select(x => BackupGapAnalyzer.NormalizeComparable(x.Root));
            IEnumerable<string> requestedRemoteRoots = m.RemoteTargets
                .SelectMany(t => t.Shares.Select(s => BackupGapAnalyzer.NormalizeComparable(s.Root)));
            return scannedRoots
                .Concat(requestedRemoteRoots)
                .Distinct(DiscoveryPathComparer.Instance)
                .OrderBy(x => x, DiscoveryPathComparer.Instance)
                .ToArray();
        }

        return ScopeEntries(previous).SequenceEqual(ScopeEntries(current), DiscoveryPathComparer.Instance);
    }

    public static int PruneSnapshots(string historyDirectory, int retainCount)
    {
        if (retainCount <= 0) return 0;
        string directory = Path.GetFullPath(historyDirectory);
        if (!Directory.Exists(directory)) return 0;
        ManifestWriter.EnsureNoReparseAncestors(directory);

        int deleted = 0;
        foreach (string file in Directory.EnumerateFiles(directory, "sbd-*.json", SearchOption.TopDirectoryOnly)
                     .OrderByDescending(File.GetLastWriteTimeUtc)
                     .Skip(retainCount))
        {
            try
            {
                if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0) continue;
                File.Delete(file);
                deleted++;
            }
            catch
            {
                // Retention cleanup is best-effort; never fail the discovery result for cleanup.
            }
        }
        return deleted;
    }

    public static string SaveSnapshot(string historyDirectory, DiscoveryManifest manifest)
    {
        string directory = Path.GetFullPath(historyDirectory);
        ManifestWriter.EnsureNoReparseAncestors(directory);
        Directory.CreateDirectory(directory);
        ManifestWriter.EnsureNoReparseAncestors(directory);
        string fileName = $"sbd-{manifest.GeneratedAtUtc:yyyyMMdd-HHmmssfff}Z-{Guid.NewGuid():N}.json";
        string path = Path.Combine(directory, fileName);
        ManifestWriter.WriteDiscovery(path, manifest);
        return path;
    }
}
