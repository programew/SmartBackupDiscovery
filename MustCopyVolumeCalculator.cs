namespace SmartBackupDiscovery;

public static class MustCopyVolumeCalculator
{
    public static MustCopyVolumeSummary Calculate(ScanResult scan)
    {
        var projectRoots = scan.ProjectVolumes.Select(x => x.Root).ToArray();
        long projectFiles = scan.ProjectVolumes.Sum(x => x.Files);
        long projectBytes = SumSaturating(scan.ProjectVolumes.Select(x => x.Bytes));

        var standaloneMustCopy = scan.Candidates
            .Where(IsMustCopyCandidate)
            .Where(candidate => !projectRoots.Any(root => SourceIdentityProvider.IsSameOrUnder(candidate.Path, root)))
            .ToArray();

        long standaloneBytes = SumSaturating(standaloneMustCopy.Select(x => Math.Max(0, x.Size)));
        long totalFiles = SaturatingAdd(projectFiles, standaloneMustCopy.LongLength);
        long totalBytes = SaturatingAdd(projectBytes, standaloneBytes);

        return new MustCopyVolumeSummary(
            totalFiles,
            totalBytes,
            projectFiles,
            projectBytes,
            standaloneMustCopy.LongLength,
            standaloneBytes,
            standaloneMustCopy.Count(x => x.MustInclude),
            SumSaturating(standaloneMustCopy.Where(x => x.MustInclude).Select(x => Math.Max(0, x.Size))),
            standaloneMustCopy.Count(x => x.ProtectionDetected),
            SumSaturating(standaloneMustCopy.Where(x => x.ProtectionDetected).Select(x => Math.Max(0, x.Size))),
            "Project source trees excluding generated/dependency directories, plus standalone Critical/MustInclude/protected Office candidates. Paths already inside a project tree are counted once.");
    }

    private static bool IsMustCopyCandidate(FileCandidate candidate) =>
        candidate.MustInclude || candidate.ProtectionDetected || candidate.Priority == BackupPriority.Critical;

    private static long SumSaturating(IEnumerable<long> values)
    {
        long total = 0;
        foreach (long value in values)
            total = SaturatingAdd(total, Math.Max(0, value));
        return total;
    }

    private static long SaturatingAdd(long current, long value) =>
        value > 0 && current > long.MaxValue - value ? long.MaxValue : current + value;
}
