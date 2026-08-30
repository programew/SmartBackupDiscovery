namespace SmartBackupDiscovery;

public static class ProjectDetector
{
    public static IReadOnlyList<BackupSet> BuildProjectSets(
        IEnumerable<string> projectRoots,
        IReadOnlyList<SourceDescriptor> sources)
    {
        var normalized = projectRoots
            .Select(SafeFullPath)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Cast<string>()
            .Distinct(PathRules.Comparer)
            .OrderBy(x => x.Length)
            .ToList();

        var selected = new List<string>();
        foreach (string root in normalized)
        {
            if (selected.Any(existing => SourceIdentityProvider.IsSameOrUnder(root, existing)))
                continue;
            selected.Add(root);
        }

        return selected.Select(root =>
        {
            string name = new DirectoryInfo(root).Name;
            var descriptor = SourceIdentityProvider.FindSourceForPath(sources, root);
            var reasons = new List<string> { "Project/source root detected from project markers or source-tree structure" };
            if (Directory.Exists(Path.Combine(root, ".git")))
                reasons.Add("Git repository metadata present");
            return new BackupSet(
                $"project:{NormalizeId(root)}",
                "Project",
                name,
                140,
                BackupPriority.High,
                new[] { root },
                reasons,
                descriptor is null ? Array.Empty<string>() : new[] { descriptor.Id });
        }).ToArray();
    }

    private static string? SafeFullPath(string value)
    {
        try { return Path.GetFullPath(value); }
        catch { return null; }
    }

    private static string NormalizeId(string value) => StableId.Hash12(value);
}
