namespace SmartBackupDiscovery;

public sealed class DiscoveryPathComparer : IEqualityComparer<string>, IComparer<string>
{
    public static DiscoveryPathComparer Instance { get; } = new();

    public bool Equals(string? x, string? y)
    {
        if (ReferenceEquals(x, y)) return true;
        if (x is null || y is null) return false;
        bool xs = RemoteLinuxPath.TryNormalizeSftpUri(x, out string xn);
        bool ys = RemoteLinuxPath.TryNormalizeSftpUri(y, out string yn);
        if (xs || ys) return xs && ys && string.Equals(xn, yn, StringComparison.Ordinal);
        return PathRules.Comparer.Equals(x, y);
    }

    public int GetHashCode(string obj)
    {
        if (RemoteLinuxPath.TryNormalizeSftpUri(obj, out string normalized))
            return StringComparer.Ordinal.GetHashCode(normalized);
        return PathRules.Comparer.GetHashCode(obj);
    }

    public int Compare(string? x, string? y)
    {
        if (ReferenceEquals(x, y)) return 0;
        if (x is null) return -1;
        if (y is null) return 1;
        bool xs = RemoteLinuxPath.TryNormalizeSftpUri(x, out string xn);
        bool ys = RemoteLinuxPath.TryNormalizeSftpUri(y, out string yn);
        if (xs && ys) return StringComparer.Ordinal.Compare(xn, yn);
        if (xs != ys) return xs ? 1 : -1;
        return PathRules.Comparer.Compare(x, y);
    }
}
