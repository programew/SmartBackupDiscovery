namespace SmartBackupDiscovery;

public sealed record PlatformTraversalOptions(
    bool CrossFileSystems = false,
    bool IncludeSystemMounts = false)
{
    public static PlatformTraversalOptions Default { get; } = new();
}

public enum PlatformSkipReason
{
    None,
    SystemVirtualFileSystem,
    ContainerRuntimeLayer,
    MountBoundary
}

public sealed class PlatformScanPolicy
{
    private static readonly string[] LinuxDefaultRootCandidates =
    {
        "/home", "/srv", "/opt", "/var/www", "/var/lib", "/etc"
    };

    private static readonly string[] LinuxVirtualRoots =
    {
        "/proc", "/sys", "/dev", "/run"
    };

    private static readonly string[] LinuxContainerRuntimeRoots =
    {
        "/var/lib/docker/overlay2",
        "/var/lib/docker/containers",
        "/var/lib/docker/image",
        "/var/lib/docker/buildkit",
        "/var/lib/containers/storage/overlay",
        "/var/lib/containers/storage/overlay-containers",
        "/var/lib/containers/storage/overlay-images",
        "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs",
        "/var/lib/containerd/io.containerd.content.v1.content",
        "/var/lib/containerd/io.containerd.metadata.v1.bolt"
    };

    private readonly PlatformTraversalOptions _options;
    private readonly HashSet<string> _explicitRoots;
    private readonly HashSet<string> _mountPoints;

    public PlatformScanPolicy(IEnumerable<string> explicitRoots, PlatformTraversalOptions options)
    {
        _options = options;
        _explicitRoots = new HashSet<string>(PathRules.Comparer);
        foreach (string root in explicitRoots)
        {
            try { _explicitRoots.Add(PathRules.Normalize(root)); } catch { }
        }
        _mountPoints = OperatingSystem.IsLinux() ? ReadLinuxMountPoints() : new HashSet<string>(PathRules.Comparer);
    }

    public static List<string> GetDefaultRoots()
    {
        if (OperatingSystem.IsLinux())
        {
            return LinuxDefaultRootCandidates
                .Where(Directory.Exists)
                .Select(Path.GetFullPath)
                .Distinct(PathRules.Comparer)
                .ToList();
        }

        return DriveInfo.GetDrives()
            .Where(d => d.IsReady && d.DriveType == DriveType.Fixed)
            .Select(d => d.RootDirectory.FullName)
            .Distinct(PathRules.Comparer)
            .ToList();
    }

    public bool ShouldSkipDirectory(string directory, string scanRoot, out PlatformSkipReason reason)
    {
        reason = PlatformSkipReason.None;
        if (!OperatingSystem.IsLinux()) return false;

        string path;
        string root;
        try
        {
            path = PathRules.Normalize(directory);
            root = PathRules.Normalize(scanRoot);
        }
        catch { return false; }

        if (!_options.IncludeSystemMounts)
        {
            if (LinuxVirtualRoots.Any(prefix => PathRules.IsSameOrUnder(path, prefix)))
            {
                reason = PlatformSkipReason.SystemVirtualFileSystem;
                return true;
            }

            if (LinuxContainerRuntimeRoots.Any(prefix => PathRules.IsSameOrUnder(path, prefix)))
            {
                reason = PlatformSkipReason.ContainerRuntimeLayer;
                return true;
            }
        }

        if (!_options.CrossFileSystems && !PathRules.EqualsPath(path, root) && _mountPoints.Contains(path))
        {
            // Explicit scan roots are always honored, even when they are separate mounts.
            if (!_explicitRoots.Contains(path))
            {
                reason = PlatformSkipReason.MountBoundary;
                return true;
            }
        }

        return false;
    }

    private static HashSet<string> ReadLinuxMountPoints()
    {
        var result = new HashSet<string>(PathRules.Comparer);
        const string mountInfo = "/proc/self/mountinfo";
        try
        {
            foreach (string line in File.ReadLines(mountInfo))
            {
                // mountinfo fields before the " - " separator: ... root mount_point options ...
                string[] parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 5) continue;
                string mountPoint = DecodeMountInfoPath(parts[4]);
                if (!Path.IsPathRooted(mountPoint)) continue;
                try { result.Add(PathRules.Normalize(mountPoint)); } catch { }
            }
        }
        catch
        {
            // Mount-boundary protection is best effort; pseudo-filesystem protection still applies.
        }
        return result;
    }

    private static string DecodeMountInfoPath(string value) => value
        .Replace("\\040", " ", StringComparison.Ordinal)
        .Replace("\\011", "\t", StringComparison.Ordinal)
        .Replace("\\012", "\n", StringComparison.Ordinal)
        .Replace("\\134", "\\", StringComparison.Ordinal);
}
