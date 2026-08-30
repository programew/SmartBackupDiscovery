using System.Net;
using System.Net.Sockets;

namespace SmartBackupDiscovery;

public static class SourceIdentityProvider
{
    public static HostIdentity GetScannerHostIdentity()
    {
        string host = Environment.MachineName;
        var v4 = new List<string>();
        var v6 = new List<string>();
        try
        {
            foreach (var address in Dns.GetHostAddresses(host))
            {
                if (address.AddressFamily == AddressFamily.InterNetwork)
                    v4.Add(address.ToString());
                else if (address.AddressFamily == AddressFamily.InterNetworkV6)
                    v6.Add(address.ToString());
            }
        }
        catch { }

        return new HostIdentity("ScannerHost", host, host, v4.Distinct().ToArray(), v6.Distinct().ToArray());
    }

    public static IReadOnlyList<SourceDescriptor> BuildSources(IEnumerable<string> roots)
    {
        var result = new List<SourceDescriptor>();
        foreach (string rootValue in roots.Distinct(PathRules.Comparer))
        {
            string root;
            try { root = Path.GetFullPath(rootValue); }
            catch { root = rootValue; }

            if (TryParseUnc(root, out string host, out string share, out _))
            {
                result.Add(new SourceDescriptor(
                    Id: $"smb:{Sanitize(host)}:{Sanitize(share)}",
                    Kind: SourceKind.Smb,
                    Root: root,
                    HostReference: host,
                    Share: share,
                    Volume: null));
                continue;
            }

            string scanner = Environment.MachineName;
            if (OperatingSystem.IsLinux())
            {
                string volume = Path.GetPathRoot(root) ?? "/";
                result.Add(new SourceDescriptor(
                    Id: $"linux:{Sanitize(scanner)}:{StableId.Hash12(root)}",
                    Kind: SourceKind.LinuxLocal,
                    Root: root,
                    HostReference: scanner,
                    Share: null,
                    Volume: volume));
                continue;
            }

            string windowsVolume = Path.GetPathRoot(root)?.TrimEnd('\\', '/').Replace(":", string.Empty) ?? "ROOT";
            result.Add(new SourceDescriptor(
                Id: $"local:{Sanitize(scanner)}:{Sanitize(windowsVolume)}",
                Kind: SourceKind.Local,
                Root: root,
                HostReference: scanner,
                Share: null,
                Volume: windowsVolume));
        }
        return result;
    }

    public static SourceDescriptor? FindSourceForPath(IReadOnlyList<SourceDescriptor> sources, string path)
    {
        SourceDescriptor? best = null;
        foreach (var source in sources)
        {
            if (!IsSameOrUnder(path, source.Root))
                continue;
            if (best is null || source.Root.Length > best.Root.Length)
                best = source;
        }
        return best;
    }

    public static bool TryParseUnc(string path, out string host, out string share, out string relative)
    {
        host = share = relative = string.Empty;
        if (!OperatingSystem.IsWindows() || !path.StartsWith(@"\\", StringComparison.Ordinal))
            return false;

        string[] parts = path.TrimStart('\\').Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2)
            return false;
        host = parts[0];
        share = parts[1];
        relative = parts.Length > 2 ? string.Join(Path.DirectorySeparatorChar, parts.Skip(2)) : string.Empty;
        return true;
    }

    public static string Sanitize(string value)
    {
        var invalid = Path.GetInvalidFileNameChars().ToHashSet();
        return new string(value.Select(ch => invalid.Contains(ch) ? '_' : ch).ToArray());
    }

    public static bool IsSameOrUnder(string path, string root) => PathRules.IsSameOrUnder(path, root);
}
