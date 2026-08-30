namespace SmartBackupDiscovery;

public static class PathRules
{
    public static StringComparer Comparer => OperatingSystem.IsWindows()
        ? StringComparer.OrdinalIgnoreCase
        : StringComparer.Ordinal;

    public static StringComparison Comparison => OperatingSystem.IsWindows()
        ? StringComparison.OrdinalIgnoreCase
        : StringComparison.Ordinal;

    public static bool EqualsPath(string left, string right) =>
        string.Equals(Normalize(left), Normalize(right), Comparison);

    public static string Normalize(string path)
    {
        string full = Path.GetFullPath(path);
        string root = Path.GetPathRoot(full) ?? string.Empty;
        if (full.Length > root.Length)
            full = full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return full;
    }

    public static bool IsSameOrUnder(string path, string root)
    {
        try
        {
            string p = Normalize(path);
            string r = Normalize(root);
            if (p.Equals(r, Comparison)) return true;
            string prefix = r.EndsWith(Path.DirectorySeparatorChar) ? r : r + Path.DirectorySeparatorChar;
            return p.StartsWith(prefix, Comparison);
        }
        catch { return false; }
    }
}
