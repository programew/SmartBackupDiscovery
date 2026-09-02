namespace SmartBackupDiscovery;

public static class DiscoveryManifestMerger
{
    public static DiscoveryManifest WithRemoteLinux(DiscoveryManifest local, RemoteLinuxScanResult remote)
    {
        if (remote.Reports.Count == 0 && remote.Sources.Count == 0) return local;

        var roots = local.ScanCoverage.Roots.Concat(remote.Coverage.Roots).ToArray();
        var coverage = new ScanCoverage(
            roots,
            Add(local.ScanCoverage.DirectoriesVisited, remote.Coverage.DirectoriesVisited),
            Add(local.ScanCoverage.FilesSeen, remote.Coverage.FilesSeen),
            Add(local.ScanCoverage.CandidatesFound, remote.Coverage.CandidatesFound),
            Add(local.ScanCoverage.PolicyDirectoriesSkipped, remote.Coverage.PolicyDirectoriesSkipped),
            Add(local.ScanCoverage.ReparseDirectoriesSkipped, remote.Coverage.ReparseDirectoriesSkipped),
            Add(local.ScanCoverage.ReparseFilesSkipped, remote.Coverage.ReparseFilesSkipped));

        var performance = new ScanPerformanceSummary(
            Add(local.Performance.ProjectFastPathFiles, remote.Performance.ProjectFastPathFiles),
            Add(local.Performance.SignatureProbesAvoided, remote.Performance.SignatureProbesAvoided),
            local.Performance.JvmProjectsDetected + remote.Performance.JvmProjectsDetected,
            Add(local.Performance.GeneratedDirectoriesSkipped, remote.Performance.GeneratedDirectoriesSkipped),
            Add(local.Performance.LinuxPolicyDirectoriesSkipped, remote.Performance.LinuxPolicyDirectoriesSkipped),
            Add(local.Performance.MountBoundariesSkipped, remote.Performance.MountBoundariesSkipped));

        var mustCopy = new MustCopyVolumeSummary(
            Add(local.MustCopyVolume.FileCount, remote.MustCopyVolume.FileCount),
            Add(local.MustCopyVolume.EstimatedBytes, remote.MustCopyVolume.EstimatedBytes),
            Add(local.MustCopyVolume.ProjectSourceFiles, remote.MustCopyVolume.ProjectSourceFiles),
            Add(local.MustCopyVolume.ProjectSourceBytes, remote.MustCopyVolume.ProjectSourceBytes),
            Add(local.MustCopyVolume.StandaloneMustCopyFiles, remote.MustCopyVolume.StandaloneMustCopyFiles),
            Add(local.MustCopyVolume.StandaloneMustCopyBytes, remote.MustCopyVolume.StandaloneMustCopyBytes),
            Add(local.MustCopyVolume.StandaloneExplicitMustIncludeFiles, remote.MustCopyVolume.StandaloneExplicitMustIncludeFiles),
            Add(local.MustCopyVolume.StandaloneExplicitMustIncludeBytes, remote.MustCopyVolume.StandaloneExplicitMustIncludeBytes),
            Add(local.MustCopyVolume.StandaloneProtectedOfficeFiles, remote.MustCopyVolume.StandaloneProtectedOfficeFiles),
            Add(local.MustCopyVolume.StandaloneProtectedOfficeBytes, remote.MustCopyVolume.StandaloneProtectedOfficeBytes),
            local.MustCopyVolume.Basis + " Remote Linux: " + remote.MustCopyVolume.Basis);

        return new DiscoveryManifest
        {
            FormatVersion = "3.4",
            ApplicationVersion = "3.4.0",
            RuleSetVersion = "discover-only-3.4-network-inventory-linux-sftp-jvm-fastpath",
            GeneratedAtUtc = local.GeneratedAtUtc,
            ScannerHost = local.ScannerHost,
            Sources = local.Sources.Concat(remote.Sources).GroupBy(x => x.Id, StringComparer.OrdinalIgnoreCase).Select(x => x.First()).ToArray(),
            RemoteTargets = local.RemoteTargets,
            RemoteLinuxTargets = remote.Reports,
            ContentInspectionProfile = local.ContentInspectionProfile,
            OfficeProtectionInspectionEnabled = local.OfficeProtectionInspectionEnabled,
            ResourcePolicy = local.ResourcePolicy,
            TraversalLimits = local.TraversalLimits,
            PlatformTraversal = local.PlatformTraversal,
            ScanCoverage = coverage,
            Candidates = local.Candidates.Concat(remote.Candidates)
                .GroupBy(x => $"{x.SourceId}|{x.Path}", StringComparer.Ordinal)
                .Select(x => x.OrderByDescending(c => c.Score).First())
                .OrderByDescending(x => x.Score).ThenBy(x => x.Path, StringComparer.Ordinal).ToArray(),
            BackupSets = local.BackupSets.Concat(remote.BackupSets)
                .GroupBy(x => x.Id, StringComparer.OrdinalIgnoreCase).Select(x => x.First())
                .OrderByDescending(x => x.Score).ToArray(),
            Errors = local.Errors.Concat(remote.Errors).Take(10_000).ToArray(),
            ProjectVolumes = local.ProjectVolumes.Concat(remote.ProjectVolumes).ToArray(),
            Performance = performance,
            MustCopyVolume = mustCopy
        };
    }

    private static long Add(long a, long b) => b > 0 && a > long.MaxValue - b ? long.MaxValue : a + b;
}
