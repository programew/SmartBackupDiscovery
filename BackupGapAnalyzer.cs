using System.Text.Json;

namespace SmartBackupDiscovery;

public static class BackupGapAnalyzer
{
    public static BackupInventory LoadInventory(string path)
    {
        path = Path.GetFullPath(path);
        var info = new FileInfo(path);
        if (!info.Exists) throw new FileNotFoundException("Backup inventory was not found.", path);
        if (info.Length > 64L * 1024 * 1024)
            throw new InvalidDataException("Backup inventory is larger than the 64 MiB safety limit.");

        var covered = new List<string>();
        string ext = Path.GetExtension(path);

        if (ext.Equals(".json", StringComparison.OrdinalIgnoreCase))
        {
            string text = File.ReadAllText(path);
            using JsonDocument doc = JsonDocument.Parse(text);
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in doc.RootElement.EnumerateArray())
                    if (item.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(item.GetString()))
                        covered.Add(item.GetString()!);
            }
            else if (doc.RootElement.ValueKind == JsonValueKind.Object &&
                     doc.RootElement.TryGetProperty("coveredPaths", out JsonElement paths) &&
                     paths.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in paths.EnumerateArray())
                    if (item.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(item.GetString()))
                        covered.Add(item.GetString()!);
            }
            else
            {
                throw new InvalidDataException("Backup inventory JSON must be an array of paths or an object with a coveredPaths array.");
            }
        }
        else
        {
            foreach (string raw in File.ReadLines(path))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line.StartsWith('#')) continue;
                string first = ParseFirstCsvField(line).Trim();
                if (first.Equals("path", StringComparison.OrdinalIgnoreCase) ||
                    first.Equals("root", StringComparison.OrdinalIgnoreCase) ||
                    first.Equals("coveredPath", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (first.Length > 0) covered.Add(first);
            }
        }

        if (covered.Count > 100_000)
            throw new InvalidDataException("Backup inventory exceeds the 100,000-entry safety limit.");

        string[] normalized = covered
            .Select(NormalizeCoverageRoot)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(DiscoveryPathComparer.Instance)
            .ToArray();

        if (normalized.Length == 0)
            throw new InvalidDataException("Backup inventory contains no usable covered paths.");

        return new BackupInventory(path, normalized);
    }

    public static BackupGapSummary Analyze(DiscoveryManifest manifest, BackupInventory inventory, int topLimit = 50)
    {
        var items = new List<BackupGapItem>();
        long totalBytes = 0;
        long coveredBytes = 0;
        int coveredCandidates = 0;
        int criticalUncovered = 0;
        int highUncovered = 0;

        foreach (FileCandidate candidate in manifest.Candidates)
        {
            string? coveredBy = FindCoveringRoot(candidate.Path, inventory.CoveredPaths);
            bool covered = coveredBy is not null;
            totalBytes = SizeMath.AddSaturating(totalBytes, Math.Max(0, candidate.Size));
            if (covered)
            {
                coveredCandidates++;
                coveredBytes = SizeMath.AddSaturating(coveredBytes, Math.Max(0, candidate.Size));
            }
            else
            {
                if (candidate.Priority == BackupPriority.Critical) criticalUncovered++;
                if (candidate.Priority == BackupPriority.High) highUncovered++;
                items.Add(new BackupGapItem(
                    "Candidate",
                    candidate.Path,
                    candidate.Size,
                    candidate.Priority,
                    candidate.Category.ToString(),
                    false,
                    null));
            }
        }

        int coveredSets = 0;
        foreach (BackupSet set in manifest.BackupSets)
        {
            bool covered = set.SourcePaths.Count > 0 && set.SourcePaths.All(path => FindCoveringRoot(path, inventory.CoveredPaths) is not null);
            if (covered)
            {
                coveredSets++;
                continue;
            }

            foreach (string path in set.SourcePaths.Where(path => FindCoveringRoot(path, inventory.CoveredPaths) is null))
            {
                items.Add(new BackupGapItem(
                    "BackupSet",
                    path,
                    null,
                    set.Priority,
                    set.Type,
                    false,
                    null));
            }
        }

        var top = items
            .OrderByDescending(x => (int)x.Priority)
            .ThenByDescending(x => x.Size ?? 0)
            .ThenBy(x => x.Path, DiscoveryPathComparer.Instance)
            .Take(Math.Clamp(topLimit, 1, 500))
            .ToArray();

        return new BackupGapSummary(
            true,
            inventory.CoveredPaths.Count,
            totalBytes,
            coveredBytes,
            Math.Max(0, totalBytes - coveredBytes),
            manifest.Candidates.Count,
            coveredCandidates,
            manifest.Candidates.Count - coveredCandidates,
            criticalUncovered,
            highUncovered,
            manifest.BackupSets.Count,
            coveredSets,
            manifest.BackupSets.Count - coveredSets,
            top);
    }

    internal static string? FindCoveringRoot(string path, IReadOnlyList<string> roots)
    {
        string normalizedPath = NormalizeComparable(path);
        bool pathIsSftp = RemoteLinuxPath.TryNormalizeSftpUri(normalizedPath, out string normalizedSftpPath);
        foreach (string root in roots)
        {
            string normalizedRoot = NormalizeComparable(root);
            bool rootIsSftp = RemoteLinuxPath.TryNormalizeSftpUri(normalizedRoot, out string normalizedSftpRoot);
            if (pathIsSftp || rootIsSftp)
            {
                if (pathIsSftp && rootIsSftp && RemoteLinuxPath.IsSameOrUnderSftpUri(normalizedSftpPath, normalizedSftpRoot))
                    return root;
                continue;
            }

            if (normalizedPath.Equals(normalizedRoot, PathRules.Comparison))
                return root;
            char separator = Path.DirectorySeparatorChar;
            string prefix = normalizedRoot.EndsWith(separator) ? normalizedRoot : normalizedRoot + separator;
            if (normalizedPath.StartsWith(prefix, PathRules.Comparison))
                return root;
        }
        return null;
    }

    private static string NormalizeCoverageRoot(string path)
    {
        string expanded = Environment.ExpandEnvironmentVariables(path.Trim().Trim('"'));
        if (expanded.IndexOfAny(['*', '?']) >= 0)
            throw new InvalidDataException($"Backup inventory path must be explicit and cannot contain wildcards: {expanded}");
        if (RemoteLinuxPath.TryNormalizeSftpUri(expanded, out string sftp))
            return sftp;
        if (!Path.IsPathRooted(expanded))
            throw new InvalidDataException($"Backup inventory path must be absolute or an sftp:// host path: {expanded}");
        string canonical = Path.GetFullPath(expanded);
        return NormalizeComparable(canonical);
    }

    internal static string NormalizeComparable(string path)
    {
        string value = path.Trim().Trim('"');
        if (RemoteLinuxPath.TryNormalizeSftpUri(value, out string sftp))
            return sftp;
        if (OperatingSystem.IsWindows())
        {
            value = value.Replace('/', '\\');
            string root = Path.GetPathRoot(value) ?? string.Empty;
            while (value.Length > root.Length && value.EndsWith('\\')) value = value[..^1];
            return value;
        }

        value = value.Replace('\\', '/');
        while (value.Length > 1 && value.EndsWith('/')) value = value[..^1];
        return value;
    }

    private static string ParseFirstCsvField(string line)
    {
        if (!line.StartsWith('"'))
        {
            int comma = line.IndexOf(',');
            return comma < 0 ? line : line[..comma];
        }

        var chars = new List<char>();
        for (int i = 1; i < line.Length; i++)
        {
            if (line[i] == '"')
            {
                if (i + 1 < line.Length && line[i + 1] == '"')
                {
                    chars.Add('"');
                    i++;
                    continue;
                }
                break;
            }
            chars.Add(line[i]);
        }
        return new string(chars.ToArray());
    }
}
