namespace SmartBackupDiscovery;

public sealed record LinuxFileHint(
    FileCategory Category,
    int Score,
    string RuleId,
    string Summary,
    bool MustInclude);

public static class LinuxBackupHints
{
    private static readonly HashSet<string> ExactImportantFiles = new(StringComparer.Ordinal)
    {
        "/etc/fstab",
        "/etc/crypttab",
        "/etc/hosts",
        "/etc/hostname",
        "/etc/resolv.conf",
        "/etc/crontab",
        "/etc/ssh/sshd_config",
        "/etc/samba/smb.conf"
    };


    private static readonly string[] MetadataOnlyRoots =
    {
        "/etc",
        "/var/lib/postgresql",
        "/var/lib/mysql",
        "/var/lib/mariadb",
        "/var/lib/redis"
    };

    private static readonly string[] ImportantConfigRoots =
    {
        "/etc/nginx",
        "/etc/apache2",
        "/etc/httpd",
        "/etc/systemd/system",
        "/etc/docker",
        "/etc/containers",
        "/etc/postgresql",
        "/etc/mysql",
        "/etc/mariadb",
        "/etc/redis",
        "/etc/samba",
        "/etc/netplan",
        "/etc/NetworkManager/system-connections"
    };

    public static bool ShouldAvoidSignatureProbe(string path)
    {
        if (!OperatingSystem.IsLinux()) return false;
        try
        {
            string normalized = PathRules.Normalize(path);
            return MetadataOnlyRoots.Any(root => PathRules.IsSameOrUnder(normalized, root));
        }
        catch { return false; }
    }

    public static LinuxFileHint? GetHint(string path)
    {
        if (!OperatingSystem.IsLinux()) return null;
        string normalized;
        try { normalized = PathRules.Normalize(path); }
        catch { return null; }
        return GetHintForNormalizedLinuxPath(normalized);
    }

    public static LinuxFileHint? GetHintForRemotePath(string remoteLinuxPath)
    {
        string normalized = RemoteLinuxPath.NormalizeAbsolute(remoteLinuxPath);
        return GetHintForNormalizedLinuxPath(normalized);
    }

    public static bool IsMetadataOnlyRemotePath(string remoteLinuxPath)
    {
        string normalized = RemoteLinuxPath.NormalizeAbsolute(remoteLinuxPath);
        return MetadataOnlyRoots.Any(root => RemoteLinuxPath.IsSameOrUnder(normalized, root));
    }

    private static LinuxFileHint? GetHintForNormalizedLinuxPath(string normalized)
    {
        if (ExactImportantFiles.Contains(normalized))
            return new LinuxFileHint(FileCategory.Configuration, 145, "LINUX_ESSENTIAL_CONFIG",
                "Important Linux host configuration file", true);

        if (ImportantConfigRoots.Any(root => RemoteLinuxPath.IsSameOrUnder(normalized, root)))
            return new LinuxFileHint(FileCategory.Configuration, 135, "LINUX_SERVICE_CONFIG",
                "Configuration for a Linux service or host subsystem", true);

        string name = RemoteLinuxPath.GetName(normalized);
        if (name.Equals("docker-compose.yml", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("docker-compose.yaml", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("compose.yml", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("compose.yaml", StringComparison.OrdinalIgnoreCase))
            return new LinuxFileHint(FileCategory.Configuration, 135, "LINUX_COMPOSE_CONFIG",
                "Container composition configuration", true);

        return null;
    }
}
