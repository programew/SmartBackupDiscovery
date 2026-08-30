namespace SmartBackupDiscovery;

public sealed class DiscoveryEngine
{
    public DiscoveryManifest Discover(
        IReadOnlyList<string> roots,
        bool inspectOfficeProtection,
        ContentInspectionProfile profile,
        ResourcePolicy resourcePolicy,
        TraversalLimits traversalLimits,
        Action<ScanProgress>? progress = null,
        Action<FileCandidate>? onCandidate = null,
        IReadOnlyList<RemoteTargetReport>? remoteTargets = null,
        IReadOnlyList<string>? preScanErrors = null,
        PlatformTraversalOptions? platformTraversal = null)
    {
        var scanner = SourceIdentityProvider.GetScannerHostIdentity();
        var sources = SourceIdentityProvider.BuildSources(roots);
        var governor = new ResourceGovernor(resourcePolicy);
        var scan = new FileScanner().Scan(
            roots,
            sources,
            inspectOfficeProtection,
            profile,
            governor,
            traversalLimits,
            progress,
            onCandidate,
            platformTraversal);

        var sets = new List<BackupSet>();
        sets.AddRange(ProjectDetector.BuildProjectSets(scan.ProjectRoots, sources));
        sets.AddRange(BuildDatabaseSets(scan.Candidates));
        sets.AddRange(LinuxServiceDetector.BuildServiceSets(roots, sources));
        MustCopyVolumeSummary mustCopy = MustCopyVolumeCalculator.Calculate(scan);

        return new DiscoveryManifest
        {
            ScannerHost = scanner,
            Sources = sources,
            RemoteTargets = remoteTargets ?? Array.Empty<RemoteTargetReport>(),
            ContentInspectionProfile = profile,
            OfficeProtectionInspectionEnabled = inspectOfficeProtection,
            ResourcePolicy = resourcePolicy,
            TraversalLimits = traversalLimits,
            PlatformTraversal = platformTraversal ?? PlatformTraversalOptions.Default,
            ScanCoverage = scan.Coverage,
            Candidates = scan.Candidates,
            BackupSets = sets.OrderByDescending(x => x.Score).ToArray(),
            ProjectVolumes = scan.ProjectVolumes,
            Performance = scan.Performance,
            MustCopyVolume = mustCopy,
            Errors = (preScanErrors ?? Array.Empty<string>()).Concat(scan.Errors).ToArray()
        };
    }

    private static IReadOnlyList<BackupSet> BuildDatabaseSets(IReadOnlyList<FileCandidate> candidates)
    {
        var dbCandidates = candidates.Where(x => x.Category == FileCategory.Database).ToArray();
        if (dbCandidates.Length == 0)
            return Array.Empty<BackupSet>();

        return dbCandidates
            .GroupBy(x => Path.GetDirectoryName(x.Path) ?? x.Path, PathRules.Comparer)
            .Select(group =>
            {
                var first = group.First();
                return new BackupSet(
                    $"database:{StableId.Hash12(group.Key)}",
                    "DatabaseFiles",
                    new DirectoryInfo(group.Key).Name,
                    Math.Max(180, group.Max(x => x.Score)),
                    BackupPriority.Critical,
                    group.Select(x => x.Path).ToArray(),
                    new[] { "Database files detected by file type or signature" },
                    group.Select(x => x.SourceId).Distinct(StringComparer.OrdinalIgnoreCase).ToArray());
            })
            .ToArray();
    }
}
