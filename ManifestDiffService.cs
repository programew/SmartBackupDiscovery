namespace SmartBackupDiscovery;

public static class ManifestDiffService
{
    public static ScanDiffSummary Compare(DiscoveryManifest previous, DiscoveryManifest current, string? previousReference = null, int topLimit = 50)
    {
        var previousMap = previous.Candidates.ToDictionary(Key, StringComparer.Ordinal);
        var currentMap = current.Candidates.ToDictionary(Key, StringComparer.Ordinal);
        var changes = new List<ScanChange>();
        long addedBytes = 0;
        long removedBytes = 0;
        int added = 0;
        int removed = 0;
        int changed = 0;

        foreach (var pair in currentMap)
        {
            if (!previousMap.TryGetValue(pair.Key, out FileCandidate? old))
            {
                added++;
                addedBytes = SizeMath.AddSaturating(addedBytes, Math.Max(0, pair.Value.Size));
                changes.Add(new ScanChange("Added", pair.Value.Path, null, pair.Value.Size, null, pair.Value.Priority, null, pair.Value.Category));
                continue;
            }

            FileCandidate now = pair.Value;
            if (IsChanged(old, now))
            {
                changed++;
                changes.Add(new ScanChange("Changed", now.Path, old.Size, now.Size, old.Priority, now.Priority, old.Category, now.Category));
            }
        }

        foreach (var pair in previousMap)
        {
            if (currentMap.ContainsKey(pair.Key)) continue;
            removed++;
            removedBytes = SizeMath.AddSaturating(removedBytes, Math.Max(0, pair.Value.Size));
            changes.Add(new ScanChange("Removed", pair.Value.Path, pair.Value.Size, null, pair.Value.Priority, null, pair.Value.Category, null));
        }

        var top = changes
            .OrderByDescending(x => ChangeRank(x.ChangeType))
            .ThenByDescending(x => (int)(x.CurrentPriority ?? x.PreviousPriority ?? BackupPriority.Ignore))
            .ThenByDescending(x => x.CurrentSize ?? x.PreviousSize ?? 0)
            .Take(Math.Clamp(topLimit, 1, 500))
            .ToArray();

        return new ScanDiffSummary(
            true,
            previous.GeneratedAtUtc,
            previousReference,
            added,
            removed,
            changed,
            addedBytes,
            removedBytes,
            top);
    }

    public static ScanDiffSummary NoPrevious() => new(
        false, null, null, 0, 0, 0, 0, 0, Array.Empty<ScanChange>());

    private static string Key(FileCandidate candidate)
    {
        string path = BackupGapAnalyzer.NormalizeComparable(candidate.Path);
        if (!RemoteLinuxPath.TryNormalizeSftpUri(path, out _) && OperatingSystem.IsWindows())
            path = path.ToUpperInvariant();
        return $"{candidate.SourceId.ToUpperInvariant()}|{path}";
    }

    private static bool IsChanged(FileCandidate old, FileCandidate now) =>
        old.Size != now.Size ||
        old.LastWriteTimeUtc != now.LastWriteTimeUtc ||
        old.Score != now.Score ||
        old.Priority != now.Priority ||
        old.Category != now.Category ||
        old.ProtectionDetected != now.ProtectionDetected ||
        !string.Equals(old.ProtectionType, now.ProtectionType, StringComparison.Ordinal);

    private static int ChangeRank(string type) => type switch
    {
        "Added" => 3,
        "Changed" => 2,
        "Removed" => 1,
        _ => 0
    };
}
