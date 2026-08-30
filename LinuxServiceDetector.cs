namespace SmartBackupDiscovery;

public static class LinuxServiceDetector
{
    private sealed record KnownService(string Path, string Name, string BackupGuidance);

    private static readonly KnownService[] KnownServices =
    {
        new("/var/lib/postgresql", "PostgreSQL", "Use a PostgreSQL-aware backup or a consistent storage snapshot; raw live files alone are not considered a valid logical backup."),
        new("/var/lib/mysql", "MySQL/MariaDB", "Use a MySQL/MariaDB-aware backup or a consistent storage snapshot; raw live files alone may be inconsistent."),
        new("/var/lib/mariadb", "MariaDB", "Use a MariaDB-aware backup or a consistent storage snapshot; raw live files alone may be inconsistent."),
        new("/var/lib/redis", "Redis", "Protect Redis persistence data and configuration with a consistent snapshot/backup policy."),
        new("/var/lib/libvirt/images", "libvirt/KVM virtual machines", "Protect VM disks with a hypervisor-aware or filesystem-consistent backup method."),
        new("/var/lib/docker/volumes", "Docker persistent volumes", "Protect persistent container volumes using workload-aware or filesystem-consistent backup methods."),
        new("/var/lib/containers/storage/volumes", "Container persistent volumes", "Protect persistent container volumes using workload-aware or filesystem-consistent backup methods.")
    };

    public static IReadOnlyList<BackupSet> BuildServiceSets(
        IReadOnlyList<string> scanRoots,
        IReadOnlyList<SourceDescriptor> sources)
    {
        if (!OperatingSystem.IsLinux()) return Array.Empty<BackupSet>();

        var result = new List<BackupSet>();
        foreach (KnownService service in KnownServices)
        {
            if (!Directory.Exists(service.Path)) continue;
            if (!scanRoots.Any(root => SourceIdentityProvider.IsSameOrUnder(service.Path, root))) continue;

            SourceDescriptor? descriptor = SourceIdentityProvider.FindSourceForPath(sources, service.Path);
            result.Add(new BackupSet(
                $"linux-service:{StableId.Hash12(service.Path)}",
                "LinuxServiceData",
                service.Name,
                190,
                BackupPriority.Critical,
                new[] { service.Path },
                new[]
                {
                    "Persistent Linux service data detected in a standard service location",
                    service.BackupGuidance,
                    "Discovery-only: SmartBackupDiscovery does not copy, snapshot, stop, or back up the service"
                },
                descriptor is null ? Array.Empty<string>() : new[] { descriptor.Id }));
        }
        return result;
    }
}
