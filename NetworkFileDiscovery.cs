using System.Net;

namespace SmartBackupDiscovery;

public sealed record NetworkFileTargets(
    IReadOnlyList<string> WindowsHosts,
    IReadOnlyList<string> LinuxHosts,
    int SkippedHosts)
{
    public bool HasTargets => WindowsHosts.Count > 0 || LinuxHosts.Count > 0;
}

// Shared by GUI and CLI. Targets always come from this run's inventory;
// saved local roots, hosts and hosts files must not leak into an automatic run.
internal static class NetworkFileDiscovery
{
    private static readonly HashSet<string> TargetOptions = new(StringComparer.OrdinalIgnoreCase)
    {
        "--root", "--host", "--hosts-file", "--linux-host", "--linux-hosts-file"
    };

    private static readonly HashSet<string> FileValueOptions = new(StringComparer.OrdinalIgnoreCase)
    {
        "--remote-share", "--username", "--password", "--linux-root", "--linux-username",
        "--linux-password", "--ssh-port", "--ssh-timeout-seconds", "--ssh-host-key-sha256",
        "--ssh-known-hosts", "--ssh-key", "--config-passphrase", "--manifest", "--backup-inventory",
        "--history-dir", "--history-retain", "--report-dir", "--content-profile",
        "--max-cpu-percent", "--network-limit-mbps", "--per-host-network-limit-mbps",
        "--io-buffer-kib", "--max-adaptive-delay-ms", "--max-files", "--max-directories",
        "--max-depth", "--host-delay-ms"
    };

    private static readonly HashSet<string> FileFlags = new(StringComparer.OrdinalIgnoreCase)
    {
        "--password-stdin", "--linux-password-stdin", "--config-passphrase-stdin",
        "--ssh-key-passphrase-stdin", "--ssh-key-passphrase-prompt", "--ssh-trust-on-first-use",
        "--privacy-mode", "--no-history", "--no-report", "--no-content-scan",
        "--no-office-protection-scan", "--cross-filesystems", "--include-system-mounts", "--no-checkpoint"
    };

    private static readonly HashSet<string> NetworkValueOptions = new(StringComparer.OrdinalIgnoreCase)
    {
        "--config", "--cidr", "--exclude-cidr", "--output", "--csv", "--targets-dir", "--probe-port",
        "--probe-timeout-ms", "--network-concurrency", "--max-hosts", "--max-probes-per-second",
        "--network-history-dir", "--network-history-retain"
    };

    public static bool IsEnabled(string[] args)
    {
        bool enabled = false;
        foreach (var option in Options(args))
        {
            if (option.Name.Equals("--auto-discover", StringComparison.OrdinalIgnoreCase)) enabled = true;
            if (option.Name.Equals("--no-auto-discover", StringComparison.OrdinalIgnoreCase)) enabled = false;
        }
        return enabled;
    }

    public static string[] BuildFileArguments(string[] userArgs, ScanConfiguration? configuration)
    {
        var result = new List<string> { "discover" };
        if (configuration is not null)
            Append(configuration.FileArguments(), rejectTargets: false);
        Append(userArgs.Skip(1), rejectTargets: true);
        return result.ToArray();

        void Append(IEnumerable<string> source, bool rejectTargets)
        {
            foreach (var option in Options(source))
            {
                if (TargetOptions.Contains(option.Name))
                {
                    if (rejectTargets)
                        throw new ArgumentException("Automatic file discovery uses only newly discovered hosts. Use discover for explicit --root/--host/hosts-file targets.");
                    continue;
                }
                if (!FileValueOptions.Contains(option.Name) && !FileFlags.Contains(option.Name)) continue;
                result.Add(option.Name);
                if (option.Value is not null) result.Add(option.Value);
            }
        }
    }

    public static string? Value(IEnumerable<string> args, string name) => Options(args)
        .LastOrDefault(x => x.Name.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;

    public static int SshPort(IEnumerable<string> args)
    {
        string? value = Value(args, "--ssh-port");
        if (value is null) return 22;
        if (!int.TryParse(value, out int port) || port is < 1 or > 65535)
            throw new ArgumentException("--ssh-port must be between 1 and 65535.");
        return port;
    }

    public static void ValidateSettings(string[] fileArgs, bool supportsSmb)
    {
        bool smb = supportsSmb && !string.IsNullOrWhiteSpace(Value(fileArgs, "--username"));
        bool ssh = !string.IsNullOrWhiteSpace(Value(fileArgs, "--linux-username"));
        if (!smb && !ssh)
            throw new ArgumentException("Automatic file discovery needs an SMB username (Windows only) or a Linux SSH username in Discover files settings or CLI options.");
        if (smb && string.IsNullOrWhiteSpace(Value(fileArgs, "--remote-share")))
            throw new ArgumentException("Automatic SMB discovery needs at least one explicit --remote-share / Windows share.");
        if (ssh && string.IsNullOrWhiteSpace(Value(fileArgs, "--linux-root")))
            throw new ArgumentException("Automatic SFTP discovery needs at least one --linux-root / Linux root.");
        if (smb)
            AuthorizedRemoteAccess.LoadTargets(Array.Empty<string>(), null,
                Options(fileArgs).Where(x => x.Name.Equals("--remote-share", StringComparison.OrdinalIgnoreCase)).Select(x => x.Value!).ToArray());
        if (ssh)
        {
            foreach (var option in Options(fileArgs).Where(x => x.Name.Equals("--linux-root", StringComparison.OrdinalIgnoreCase)))
                _ = RemoteLinuxPath.NormalizeAbsolute(option.Value!);
            _ = RemoteLinuxSftpDiscovery.NormalizeFingerprint(Value(fileArgs, "--ssh-host-key-sha256"));
        }
        _ = SshPort(fileArgs);
    }

    public static NetworkFileTargets SelectTargets(NetworkInventoryManifest inventory,
        bool useSmb, bool useSftp, int sshPort)
    {
        var scopes = inventory.Scopes.Select(x => Ipv4Cidr.Parse(x.Cidr)).ToArray();
        var exclusions = inventory.ExcludedCidrs.Select(Ipv4Cidr.Parse).ToArray();
        var windows = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var linux = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var skipped = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (NetworkDiscoveredHost host in inventory.Hosts)
        {
            bool selected = false;
            if (host.Reachability != "NeighborCacheOnly" && IPAddress.TryParse(host.IpAddress, out var ip) &&
                scopes.Any(x => x.IsPrivateScope() && x.Contains(ip)) && !exclusions.Any(x => x.Contains(ip)))
            {
                string address = ip.ToString();
                if (useSmb && host.OpenTcpPorts.Contains(445)) { windows.Add(address); selected = true; }
                if (useSftp && host.OpenTcpPorts.Contains(sshPort)) { linux.Add(address); selected = true; }
            }
            if (!selected) skipped.Add(host.IpAddress);
        }
        return new NetworkFileTargets(windows.Order().ToArray(), linux.Order().ToArray(), skipped.Count);
    }

    public static bool CanStart(int exitCode, bool cancelled, NetworkInventoryManifest? inventory) =>
        exitCode == 0 && !cancelled && inventory is not null && inventory.Errors.Count == 0;

    public static int RunAfterInventory(NetworkInventoryManifest inventory, string[] fileArgs,
        ScanConfiguration? configuration, bool supportsSmb,
        Func<string[], ScanConfiguration?, int> runDiscovery)
    {
        if (!CanStart(0, false, inventory)) return 1;
        NetworkFileTargets targets = SelectTargets(inventory,
            supportsSmb && !string.IsNullOrWhiteSpace(Value(fileArgs, "--username")),
            !string.IsNullOrWhiteSpace(Value(fileArgs, "--linux-username")), SshPort(fileArgs));
        Console.WriteLine($"Automatic file discovery: {targets.WindowsHosts.Count} SMB, {targets.LinuxHosts.Count} SFTP target(s); {targets.SkippedHosts} host(s) skipped.");
        if (!targets.HasTargets)
        {
            Console.WriteLine("No compatible service targets found; file discovery was not started.");
            return 0;
        }
        var args = fileArgs.ToList();
        foreach (string host in targets.WindowsHosts) { args.Add("--host"); args.Add(host); }
        foreach (string host in targets.LinuxHosts) { args.Add("--linux-host"); args.Add(host); }
        return runDiscovery(args.ToArray(), configuration);
    }

    public static void ValidateOutputPaths(string inventoryPath, string csvPath, string manifestPath)
    {
        string manifest = Path.GetFullPath(manifestPath);
        if (manifest.Equals(Path.GetFullPath(inventoryPath), PathRules.Comparison) ||
            manifest.Equals(Path.GetFullPath(csvPath), PathRules.Comparison))
            throw new ArgumentException("File manifest and network inventory JSON/CSV must use different output paths.");
    }

    internal static IEnumerable<(string Name, string? Value)> Options(IEnumerable<string> args)
    {
        using var iterator = args.GetEnumerator();
        while (iterator.MoveNext())
        {
            string name = iterator.Current;
            if (FileValueOptions.Contains(name) || NetworkValueOptions.Contains(name) || TargetOptions.Contains(name))
            {
                if (!iterator.MoveNext()) throw new ArgumentException($"Missing value for {name}.");
                yield return (name, iterator.Current);
            }
            else yield return (name, null);
        }
    }
}
