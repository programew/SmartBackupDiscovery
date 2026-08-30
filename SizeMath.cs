namespace SmartBackupDiscovery;

public static class SizeMath
{
    public static long AddSaturating(long left, long right)
    {
        if (right <= 0) return Math.Max(0, left);
        if (left >= long.MaxValue - right) return long.MaxValue;
        return left + right;
    }

    public static long SumCandidateBytes(IEnumerable<FileCandidate> candidates)
    {
        long total = 0;
        foreach (FileCandidate candidate in candidates)
            total = AddSaturating(total, Math.Max(0, candidate.Size));
        return total;
    }
}
