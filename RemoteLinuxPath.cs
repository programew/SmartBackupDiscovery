namespace SmartBackupDiscovery;

public static class RemoteLinuxPath
{
    public static string NormalizeAbsolute(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("Linux path cannot be empty.");
        string value = path.Trim().Replace('\\', '/');
        if (!value.StartsWith('/', StringComparison.Ordinal))
            throw new ArgumentException($"Linux path must be absolute: {path}");

        var parts = new List<string>();
        foreach (string part in value.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            if (part == ".") continue;
            if (part == "..")
            {
                if (parts.Count == 0)
                    throw new ArgumentException($"Linux path escapes root: {path}");
                parts.RemoveAt(parts.Count - 1);
                continue;
            }
            if (part.IndexOf('\0') >= 0)
                throw new ArgumentException("Linux path contains a NUL character.");
            parts.Add(part);
        }
        return parts.Count == 0 ? "/" : "/" + string.Join('/', parts);
    }

    public static string Combine(string parent, string name)
    {
        string p = NormalizeAbsolute(parent);
        if (string.IsNullOrWhiteSpace(name) || name is "." or ".." || name.Contains('/') || name.Contains('\\') || name.IndexOf('\0') >= 0)
            throw new ArgumentException($"Invalid Linux path component: {name}");
        return p == "/" ? "/" + name : p + "/" + name;
    }

    public static string GetName(string path)
    {
        string p = NormalizeAbsolute(path);
        if (p == "/") return "/";
        int slash = p.LastIndexOf('/');
        return slash < 0 ? p : p[(slash + 1)..];
    }

    public static string? GetParent(string path)
    {
        string p = NormalizeAbsolute(path);
        if (p == "/") return null;
        int slash = p.LastIndexOf('/');
        return slash <= 0 ? "/" : p[..slash];
    }

    public static bool IsSameOrUnder(string path, string root)
    {
        string p = NormalizeAbsolute(path);
        string r = NormalizeAbsolute(root);
        if (p.Equals(r, StringComparison.Ordinal)) return true;
        if (r == "/") return p.StartsWith('/', StringComparison.Ordinal);
        return p.StartsWith(r + "/", StringComparison.Ordinal);
    }

    public static string ToSftpUri(string host, int port, string path)
    {
        string normalized = NormalizeAbsolute(path);
        string hostPart = host.Contains(':') && !host.StartsWith('[', StringComparison.Ordinal) ? $"[{host}]" : host;
        string portPart = port == 22 ? string.Empty : $":{port}";
        return $"sftp://{hostPart}{portPart}{normalized}";
    }

    public static bool TryNormalizeSftpUri(string input, out string normalized)
    {
        normalized = string.Empty;
        if (!Uri.TryCreate(input.Trim(), UriKind.Absolute, out Uri? uri) ||
            !uri.Scheme.Equals("sftp", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(uri.Host))
            return false;
        int port = uri.IsDefaultPort ? 22 : uri.Port;
        string path;
        try { path = NormalizeAbsolute(Uri.UnescapeDataString(uri.AbsolutePath)); }
        catch { return false; }
        normalized = ToSftpUri(uri.Host.ToLowerInvariant(), port, path);
        return true;
    }

    public static bool IsSameOrUnderSftpUri(string path, string root)
    {
        if (!TrySplitSftpUri(path, out string ph, out int pp, out string ppath) ||
            !TrySplitSftpUri(root, out string rh, out int rp, out string rpath))
            return false;
        return pp == rp && ph.Equals(rh, StringComparison.OrdinalIgnoreCase) && IsSameOrUnder(ppath, rpath);
    }

    public static bool TrySplitSftpUri(string value, out string host, out int port, out string path)
    {
        host = path = string.Empty;
        port = 22;
        if (!Uri.TryCreate(value.Trim(), UriKind.Absolute, out Uri? uri) ||
            !uri.Scheme.Equals("sftp", StringComparison.OrdinalIgnoreCase) || string.IsNullOrWhiteSpace(uri.Host))
            return false;
        host = uri.Host;
        port = uri.IsDefaultPort ? 22 : uri.Port;
        try { path = NormalizeAbsolute(Uri.UnescapeDataString(uri.AbsolutePath)); }
        catch { return false; }
        return true;
    }
}
