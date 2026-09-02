namespace SmartBackupDiscovery;

public static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        if (args.Length == 0)
        {
#if WINDOWS_BUILD
            GuiLauncher.Run();
            return 0;
#else
            PrintHelp();
            return 0;
#endif
        }

        if (args.Contains("--help", StringComparer.OrdinalIgnoreCase) || args.Contains("-h", StringComparer.OrdinalIgnoreCase))
        {
            PrintHelp();
            return 0;
        }

        string command = args[0].ToLowerInvariant();
        try
        {
            return command switch
            {
                "gui" => RunGui(),
                "network-discover" or "network-inventory" => NetworkCli.Run(args),
                "discover" or "scan" => RunDiscover(args),
                "report" => RunReport(args),
                "compare" => RunCompare(args),
                "selftest" => SelfTest.Run(),
                _ => UnknownCommand(args[0])
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Fatal: {ex.Message}");
            return 1;
        }
    }

    private static int RunGui()
    {
#if WINDOWS_BUILD
        GuiLauncher.Run();
        return 0;
#else
        Console.Error.WriteLine("The graphical dashboard is available only in the net10.0-windows build. Use the CLI on Linux.");
        return 2;
#endif
    }

    private static int UnknownCommand(string command)
    {
        Console.Error.WriteLine($"Unknown command: {command}");
        PrintHelp();
        return 2;
    }

    private static int RunDiscover(string[] args)
    {
        var directHosts = GetOptions(args, "--host");
        string? hostsFile = GetOption(args, "--hosts-file");
        var remoteShares = GetOptions(args, "--remote-share");
        bool remoteModeRequested = directHosts.Count > 0 || !string.IsNullOrWhiteSpace(hostsFile);
        if (remoteModeRequested && !OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Credentialed SMB Authorized Remote Discover is Windows-only. On Linux, run the cross-platform CLI locally on the target host or scan an already-mounted path with --root.");

        var remoteTargets = AuthorizedRemoteAccess.LoadTargets(directHosts, hostsFile, remoteShares);
        if (remoteModeRequested && remoteTargets.Count == 0)
            throw new ArgumentException("Authorized Remote Discover was requested, but the explicit host allowlist is empty.");
        bool remoteRequested = remoteTargets.Count > 0;

        var linuxDirectHosts = GetOptions(args, "--linux-host");
        string? linuxHostsFile = GetOption(args, "--linux-hosts-file");
        var linuxRoots = GetOptions(args, "--linux-root");
        bool linuxRemoteModeRequested = linuxDirectHosts.Count > 0 || !string.IsNullOrWhiteSpace(linuxHostsFile);
        int sshPort = GetInt(args, "--ssh-port", 22, 1, 65535);
        int sshTimeoutSeconds = GetInt(args, "--ssh-timeout-seconds", 30, 5, 600);
        string? sshHostKey = GetOption(args, "--ssh-host-key-sha256");
        bool sshTrustOnFirstUse = args.Contains("--ssh-trust-on-first-use", StringComparer.OrdinalIgnoreCase);
        string sshKnownHosts = Path.GetFullPath(GetOption(args, "--ssh-known-hosts") ?? SshKnownHostsStore.GetDefaultPath());
        var linuxTargets = RemoteLinuxSftpDiscovery.LoadTargets(linuxDirectHosts, linuxHostsFile, linuxRoots, sshPort, sshHostKey);
        if (linuxRemoteModeRequested && linuxTargets.Count == 0)
            throw new ArgumentException("Remote Linux discovery was requested, but the explicit Linux host allowlist is empty.");
        bool linuxRemoteRequested = linuxTargets.Count > 0;
        bool anyRemoteRequested = remoteModeRequested || linuxRemoteModeRequested;

        var roots = GetOptions(args, "--root");
        if (roots.Count == 0 && !anyRemoteRequested)
            roots = PlatformScanPolicy.GetDefaultRoots();
        if (roots.Count == 0 && !anyRemoteRequested)
        {
            Console.Error.WriteLine("No scan roots are available. Use --root <path>, --host/--hosts-file for Windows SMB, or --linux-host/--linux-hosts-file for Linux SFTP discovery.");
            return 2;
        }

        string manifestPath = Path.GetFullPath(GetOption(args, "--manifest") ?? Path.Combine(Environment.CurrentDirectory, "discovery-manifest.json"));
        string historyDirectory = Path.GetFullPath(GetOption(args, "--history-dir") ?? ManifestHistoryService.GetDefaultHistoryDirectory(manifestPath));
        string reportDirectory = Path.GetFullPath(GetOption(args, "--report-dir") ?? Path.Combine(Path.GetDirectoryName(manifestPath) ?? Environment.CurrentDirectory, "reports"));
        string? backupInventoryPath = GetOption(args, "--backup-inventory");
        bool historyEnabled = !args.Contains("--no-history", StringComparer.OrdinalIgnoreCase);
        int historyRetain = GetInt(args, "--history-retain", 30, 0, 10_000);
        bool reportEnabled = !args.Contains("--no-report", StringComparer.OrdinalIgnoreCase);
        bool privacyMode = args.Contains("--privacy-mode", StringComparer.OrdinalIgnoreCase);

        bool inspectOffice = !args.Contains("--no-office-protection-scan", StringComparer.OrdinalIgnoreCase) &&
                             !args.Contains("--no-content-scan", StringComparer.OrdinalIgnoreCase);
        ContentInspectionProfile profile = ParseProfile(GetOption(args, "--content-profile"));

        var defaults = ResourcePolicy.Default;
        double maxCpu = GetDouble(args, "--max-cpu-percent", defaults.MaxCpuPercent, 1, 100);
        double globalNetwork = GetDouble(args, "--network-limit-mbps", defaults.GlobalNetworkMbps, 0, 100_000);
        double perHostNetwork = GetDouble(args, "--per-host-network-limit-mbps", defaults.PerHostNetworkMbps, 0, 100_000);
        int ioBufferKiB = GetInt(args, "--io-buffer-kib", defaults.IoBufferKiB, 32, 4096);
        int maxAdaptiveDelay = GetInt(args, "--max-adaptive-delay-ms", defaults.MaxAdaptiveDelayMilliseconds, 0, 5000);
        var resourcePolicy = new ResourcePolicy(maxCpu, globalNetwork, perHostNetwork, ioBufferKiB, maxAdaptiveDelay);

        var defaultLimits = TraversalLimits.Default;
        long maxFiles = GetLong(args, "--max-files", defaultLimits.MaxFiles, 1, 100_000_000);
        long maxDirs = GetLong(args, "--max-directories", defaultLimits.MaxDirectories, 1, 50_000_000);
        int maxDepth = GetInt(args, "--max-depth", defaultLimits.MaxDepth, 1, 1024);
        var limits = new TraversalLimits(maxFiles, maxDirs, maxDepth);
        var platformTraversal = new PlatformTraversalOptions(
            CrossFileSystems: args.Contains("--cross-filesystems", StringComparer.OrdinalIgnoreCase),
            IncludeSystemMounts: args.Contains("--include-system-mounts", StringComparer.OrdinalIgnoreCase));

        int hostDelayMs = GetInt(args, "--host-delay-ms", 250, 0, 60_000);
        bool checkpointEnabled = !args.Contains("--no-checkpoint", StringComparer.OrdinalIgnoreCase);
        ScanCheckpointWriter? checkpoint = null;
        bool progressLineOpen = false;
        using var remoteAccess = new AuthorizedRemoteAccess();

        var remoteReports = new List<RemoteTargetReport>();
        var preScanErrors = new List<string>();
        LinuxSftpCredential? linuxCredential = null;
        if (remoteRequested)
        {
            string? username = GetOption(args, "--username");
            if (string.IsNullOrWhiteSpace(username))
                throw new ArgumentException("--username is required when --host or --hosts-file is used.");

            bool passwordFromStdin = args.Contains("--password-stdin", StringComparer.OrdinalIgnoreCase);
            string password = passwordFromStdin
                ? AuthorizedRemoteAccess.ReadPasswordFromStdin()
                : AuthorizedRemoteAccess.ReadPasswordInteractively();

            Console.WriteLine($"Authorized Remote Discover: {remoteTargets.Count} explicit host(s); no network discovery or CIDR probing.");
            Console.WriteLine($"Remote shares: {string.Join(", ", remoteTargets.SelectMany(x => x.Shares).Distinct(StringComparer.OrdinalIgnoreCase))}");
            Console.WriteLine($"Host pacing: {hostDelayMs} ms between authentication attempts.");

            RemoteAccessResult remote = remoteAccess.Connect(remoteTargets, username, password, hostDelayMs);
            password = string.Empty;
            roots.AddRange(remote.Roots);
            remoteReports.AddRange(remote.Reports);
            preScanErrors.AddRange(remote.Errors);
        }

        if (linuxRemoteRequested)
        {
            string? linuxUsername = GetOption(args, "--linux-username");
            if (string.IsNullOrWhiteSpace(linuxUsername))
                throw new ArgumentException("--linux-username is required when --linux-host or --linux-hosts-file is used. The value may be root when that account is intentionally authorized for SSH/SFTP.");

            string? sshKey = GetOption(args, "--ssh-key");
            bool linuxPasswordStdin = args.Contains("--linux-password-stdin", StringComparer.OrdinalIgnoreCase);
            bool keyPassphraseStdin = args.Contains("--ssh-key-passphrase-stdin", StringComparer.OrdinalIgnoreCase);
            bool keyPassphrasePrompt = args.Contains("--ssh-key-passphrase-prompt", StringComparer.OrdinalIgnoreCase);
            if (!string.IsNullOrWhiteSpace(sshKey) && linuxPasswordStdin)
                throw new ArgumentException("--linux-password-stdin cannot be combined with --ssh-key.");
            if (keyPassphraseStdin && keyPassphrasePrompt)
                throw new ArgumentException("Choose only one of --ssh-key-passphrase-stdin or --ssh-key-passphrase-prompt.");

            string? linuxPassword = null;
            string? keyPassphrase = null;
            if (string.IsNullOrWhiteSpace(sshKey))
            {
                linuxPassword = linuxPasswordStdin
                    ? AuthorizedRemoteAccess.ReadPasswordFromStdin()
                    : AuthorizedRemoteAccess.ReadPasswordInteractively("Linux SSH password");
            }
            else if (keyPassphraseStdin)
            {
                keyPassphrase = AuthorizedRemoteAccess.ReadPasswordFromStdin();
            }
            else if (keyPassphrasePrompt)
            {
                keyPassphrase = AuthorizedRemoteAccess.ReadPasswordInteractively("SSH key passphrase");
            }

            linuxCredential = new LinuxSftpCredential(linuxUsername.Trim(), linuxPassword, sshKey, keyPassphrase);
            linuxPassword = string.Empty;
            keyPassphrase = string.Empty;
        }

        try
        {
            if (checkpointEnabled)
            {
                checkpoint = new ScanCheckpointWriter(manifestPath);
                Console.WriteLine($"Checkpoint: {checkpoint.CheckpointPath}");
            }

            Console.WriteLine("SmartBackupDiscovery 3.4 (.NET 10) - Automatic Network Inventory + Windows/Linux DiscoverOnly + Authorized Linux SFTP");
            Console.WriteLine($"Roots: {(roots.Count == 0 ? "(none reachable)" : string.Join(" | ", roots))}");
            Console.WriteLine($"Office protection inspection: {inspectOffice}, profile: {profile}");
            Console.WriteLine($"Resource policy: CPU <= {maxCpu:0.#}% | network <= {globalNetwork:0.#} Mbps global / {perHostNetwork:0.#} Mbps per UNC host");
            if (OperatingSystem.IsLinux())
                Console.WriteLine($"Linux traversal: cross-filesystems={platformTraversal.CrossFileSystems}, include-system-mounts={platformTraversal.IncludeSystemMounts}");

            void ShowProgress(ScanProgress p)
            {
                string line = $"Progress: {p.FilesSeen:N0} files | {p.DirectoriesVisited:N0} dirs | {p.CandidatesFound:N0} candidates | adaptive delay {p.AdaptiveDelayMilliseconds} ms | {p.CurrentDirectory}";
                if (Console.IsOutputRedirected)
                {
                    Console.WriteLine(line);
                    return;
                }
                int width;
                try { width = Math.Max(20, Console.WindowWidth - 1); } catch { width = 120; }
                if (line.Length > width) line = line[..Math.Max(1, width - 3)] + "...";
                Console.Write('\r' + line.PadRight(width));
                progressLineOpen = true;
            }

            Action<FileCandidate>? candidateAction = checkpoint is null ? null : checkpoint.Append;
            DiscoveryManifest manifest = new DiscoveryEngine().Discover(
                roots,
                inspectOffice,
                profile,
                resourcePolicy,
                limits,
                ShowProgress,
                candidateAction,
                remoteReports,
                preScanErrors,
                platformTraversal);

            if (linuxRemoteRequested && linuxCredential is not null)
            {
                Console.WriteLine($"Authorized Linux SFTP Discover: {linuxTargets.Count} explicit host(s); metadata-only; no host discovery and no SSH command execution.");
                Console.WriteLine($"SSH host-key store: {sshKnownHosts}");
                if (sshTrustOnFirstUse)
                    Console.WriteLine("SSH trust-on-first-use is enabled for previously unknown explicit hosts.");
                RemoteLinuxScanResult remoteLinux = new RemoteLinuxSftpDiscovery().Scan(
                    linuxTargets,
                    linuxCredential,
                    limits,
                    platformTraversal,
                    sshKnownHosts,
                    sshTrustOnFirstUse,
                    sshTimeoutSeconds,
                    ShowProgress,
                    candidateAction);
                manifest = DiscoveryManifestMerger.WithRemoteLinux(manifest, remoteLinux);
                linuxCredential = null;
            }

            if (progressLineOpen)
            {
                Console.WriteLine();
                progressLineOpen = false;
            }

            BackupInventory? inventory = null;
            if (!string.IsNullOrWhiteSpace(backupInventoryPath))
            {
                inventory = BackupGapAnalyzer.LoadInventory(backupInventoryPath);
                manifest.BackupGap = BackupGapAnalyzer.Analyze(manifest, inventory);
            }

            PreviousManifestResult? previous = historyEnabled
                ? ManifestHistoryService.FindPrevious(manifestPath, historyDirectory, manifest)
                : null;
            manifest.Diff = previous is null
                ? ManifestDiffService.NoPrevious()
                : ManifestDiffService.Compare(previous.Manifest, manifest, Path.GetFileName(previous.ReferencePath));
            manifest.Readiness = BackupReadinessCalculator.Calculate(manifest, manifest.BackupGap);

            ManifestWriter.WriteDiscovery(manifestPath, manifest);
            checkpoint?.Complete();

            if (historyEnabled)
            {
                try
                {
                    string snapshot = ManifestHistoryService.SaveSnapshot(historyDirectory, manifest);
                    int pruned = ManifestHistoryService.PruneSnapshots(historyDirectory, historyRetain);
                    Console.WriteLine($"History snapshot: {snapshot}");
                    if (pruned > 0) Console.WriteLine($"History retention: removed {pruned} old snapshot(s).");
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"History warning: {ex.Message}");
                }
            }

            if (reportEnabled)
            {
                try
                {
                    ManagementReportArtifacts artifacts = ManagementReportWriter.Write(reportDirectory, manifestPath, manifest, privacyMode);
                    Console.WriteLine($"HTML report: {artifacts.HtmlPath}");
                    Console.WriteLine($"PDF summary: {artifacts.PdfPath}");
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Report warning: {ex.Message}");
                }
            }

            PrintSummary(manifest, manifestPath);
            return manifest.Errors.Count == 0 ? 0 : 1;
        }
        catch
        {
            if (progressLineOpen) Console.WriteLine();
            throw;
        }
        finally
        {
            checkpoint?.Dispose();
        }
    }

    private static int RunReport(string[] args)
    {
        string manifestPath = RequireOption(args, "--manifest");
        string reportDirectory = GetOption(args, "--report-dir") ?? Path.Combine(Path.GetDirectoryName(Path.GetFullPath(manifestPath)) ?? Environment.CurrentDirectory, "reports");
        bool privacyMode = args.Contains("--privacy-mode", StringComparer.OrdinalIgnoreCase);
        DiscoveryManifest manifest = ManifestReader.Read(manifestPath);
        string? inventoryPath = GetOption(args, "--backup-inventory");
        if (!string.IsNullOrWhiteSpace(inventoryPath))
            manifest.BackupGap = BackupGapAnalyzer.Analyze(manifest, BackupGapAnalyzer.LoadInventory(inventoryPath));
        manifest.Readiness = BackupReadinessCalculator.Calculate(manifest, manifest.BackupGap);
        ManagementReportArtifacts artifacts = ManagementReportWriter.Write(reportDirectory, manifestPath, manifest, privacyMode);
        Console.WriteLine($"HTML report: {artifacts.HtmlPath}");
        Console.WriteLine($"PDF summary: {artifacts.PdfPath}");
        return 0;
    }

    private static int RunCompare(string[] args)
    {
        string currentPath = RequireOption(args, "--current");
        string previousPath = RequireOption(args, "--previous");
        DiscoveryManifest current = ManifestReader.Read(currentPath);
        DiscoveryManifest previous = ManifestReader.Read(previousPath);
        ScanDiffSummary diff = ManifestDiffService.Compare(previous, current, Path.GetFileName(previousPath));
        Console.WriteLine($"Added: {diff.AddedCount:N0} ({ManagementReportWriter.FormatBytes(diff.AddedBytes)})");
        Console.WriteLine($"Changed: {diff.ChangedCount:N0}");
        Console.WriteLine($"Removed: {diff.RemovedCount:N0} ({ManagementReportWriter.FormatBytes(diff.RemovedBytes)})");
        foreach (ScanChange change in diff.TopChanges.Take(20))
            Console.WriteLine($"{change.ChangeType,-8} {change.CurrentPriority ?? change.PreviousPriority} {change.Path}");
        return 0;
    }

    private static void PrintSummary(DiscoveryManifest manifest, string path)
    {
        Console.WriteLine($"Candidates: {manifest.Candidates.Count:N0}");
        Console.WriteLine($"Protected/encrypted Office candidates: {manifest.Candidates.Count(x => x.ProtectionDetected):N0}");
        Console.WriteLine($"Project/database sets: {manifest.BackupSets.Count:N0}");
        Console.WriteLine($"Coverage: {manifest.ScanCoverage.FilesSeen:N0} files, {manifest.ScanCoverage.DirectoriesVisited:N0} directories, {manifest.ScanCoverage.PolicyDirectoriesSkipped:N0} policy directories skipped");
        Console.WriteLine($"Candidate volume: {ManagementReportWriter.FormatBytes(SizeMath.SumCandidateBytes(manifest.Candidates))}");
        Console.WriteLine($"Must-copy estimate: {manifest.MustCopyVolume.FileCount:N0} files / {ManagementReportWriter.FormatBytes(manifest.MustCopyVolume.EstimatedBytes)}");
        Console.WriteLine($"  Project source: {manifest.MustCopyVolume.ProjectSourceFiles:N0} files / {ManagementReportWriter.FormatBytes(manifest.MustCopyVolume.ProjectSourceBytes)}");
        Console.WriteLine($"  Standalone critical/protected: {manifest.MustCopyVolume.StandaloneMustCopyFiles:N0} files / {ManagementReportWriter.FormatBytes(manifest.MustCopyVolume.StandaloneMustCopyBytes)}");
        Console.WriteLine($"Performance: {manifest.Performance.ProjectFastPathFiles:N0} project fast-path files; {manifest.Performance.SignatureProbesAvoided:N0} signature probes avoided; {manifest.Performance.JvmProjectsDetected:N0} JVM project(s) detected");
        if (manifest.Performance.LinuxPolicyDirectoriesSkipped > 0 || manifest.Performance.MountBoundariesSkipped > 0)
            Console.WriteLine($"Linux policy: {manifest.Performance.LinuxPolicyDirectoriesSkipped:N0} platform directory skips; {manifest.Performance.MountBoundariesSkipped:N0} mount boundaries skipped");
        int linuxServices = manifest.BackupSets.Count(x => x.Type == "LinuxServiceData");
        if (linuxServices > 0)
            Console.WriteLine($"Linux service data: {linuxServices:N0} critical application-aware backup set(s) detected");
        if (manifest.Readiness is { } readiness)
            Console.WriteLine($"Backup readiness: {readiness.Score}/100 (grade {readiness.Grade}, confidence {readiness.Confidence})");
        if (manifest.BackupGap is { } gap)
            Console.WriteLine($"Backup gap: {gap.UncoveredCandidateCount:N0} candidate(s) / {ManagementReportWriter.FormatBytes(gap.UncoveredCandidateBytes)} outside supplied inventory; {gap.UncoveredBackupSetCount:N0} logical set(s) uncovered");
        if (manifest.Diff is { PreviousScanAvailable: true } diff)
            Console.WriteLine($"Since previous scan: +{diff.AddedCount:N0} added, ~{diff.ChangedCount:N0} changed, -{diff.RemovedCount:N0} removed");
        foreach (var target in manifest.RemoteTargets)
            Console.WriteLine($"Remote Windows target: {target.HostReference} [{target.AuthenticationStatus}] {string.Join(", ", target.IPv4Addresses)}");
        foreach (var target in manifest.RemoteLinuxTargets)
            Console.WriteLine($"Remote Linux target: {target.HostReference}:{target.Port} [{target.AuthenticationStatus}] hostkey={(target.HostKeySha256 is null ? "unverified/unknown" : "SHA256:" + target.HostKeySha256)}");
        foreach (var root in manifest.ScanCoverage.Roots.Where(x => !x.Completed || x.Errors > 0))
            Console.WriteLine($"Coverage warning: {root.Root} (exists={root.Exists}, completed={root.Completed}, errors={root.Errors})");
        Console.WriteLine($"Manifest errors: {manifest.Errors.Count:N0}");
        Console.WriteLine($"Manifest: {Path.GetFullPath(path)}");
    }

    private static ContentInspectionProfile ParseProfile(string? value) => value?.ToLowerInvariant() switch
    {
        null or "" or "balanced" => ContentInspectionProfile.Balanced,
        "deep" => ContentInspectionProfile.Deep,
        _ => throw new ArgumentException("--content-profile must be balanced or deep.")
    };

    private static string? GetOption(string[] args, string name)
    {
        for (int i = 0; i < args.Length - 1; i++)
            if (args[i].Equals(name, StringComparison.OrdinalIgnoreCase)) return args[i + 1];
        return null;
    }

    private static string RequireOption(string[] args, string name) =>
        GetOption(args, name) ?? throw new ArgumentException($"{name} is required.");

    private static List<string> GetOptions(string[] args, string name)
    {
        var result = new List<string>();
        for (int i = 0; i < args.Length - 1; i++)
            if (args[i].Equals(name, StringComparison.OrdinalIgnoreCase)) result.Add(args[i + 1]);
        return result;
    }

    private static double GetDouble(string[] args, string name, double fallback, double min, double max)
    {
        string? value = GetOption(args, name);
        if (value is null) return fallback;
        if (!double.TryParse(value, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out double parsed) || parsed < min || parsed > max)
            throw new ArgumentException($"{name} must be between {min} and {max}.");
        return parsed;
    }

    private static int GetInt(string[] args, string name, int fallback, int min, int max)
    {
        string? value = GetOption(args, name);
        if (value is null) return fallback;
        if (!int.TryParse(value, out int parsed) || parsed < min || parsed > max)
            throw new ArgumentException($"{name} must be between {min} and {max}.");
        return parsed;
    }

    private static long GetLong(string[] args, string name, long fallback, long min, long max)
    {
        string? value = GetOption(args, name);
        if (value is null) return fallback;
        if (!long.TryParse(value, out long parsed) || parsed < min || parsed > max)
            throw new ArgumentException($"{name} must be between {min} and {max}.");
        return parsed;
    }

    private static void PrintHelp()
    {
        Console.WriteLine("""
SmartBackupDiscovery 3.4 (.NET 10 / Windows + Linux) - DiscoverOnly product edition

Commands:
  gui                        Open the Windows dashboard (Windows build only).
  network-discover [options] Inventory reachable hosts on connected/authorized private IPv4 scopes.
  network-inventory          Alias for network-discover.
  discover [options]         Discover important backup candidates and create manifest/history/reports.
  scan [options]             Alias for discover.
  report --manifest <path>   Rebuild management HTML/PDF reports from an existing manifest.
  compare --current <path> --previous <path>
                             Compare two manifests.
  selftest                   Run deterministic product/classifier/platform tests.

Controlled automatic network inventory:
  --cidr <private-cidr>      Explicit private IPv4 scope; repeat for multiple scopes.
                             Without --cidr, connected RFC1918 scopes are detected automatically.
  --authorized-scope         Required with any explicit --cidr.
  --include-local-scopes     Add connected private scopes when explicit --cidr values are supplied.
  --exclude-cidr <cidr>      Exclude a subnet or single /32 address; repeat as needed.
  --output <path>            JSON output. Default: ./network-inventory.json
  --csv <path>               CSV output. Default: beside JSON with .csv extension.
  --targets-dir <path>       Generated review lists for SMB, SFTP and unknown hosts.
  --no-target-lists          Do not create generated review lists.
  --probe-port <1-65535>     TCP service hint port; repeat. Defaults: 22 and 445.
  --no-tcp-probes            Disable TCP service probes.
  --no-icmp                  Disable ICMP echo probes.
  --no-dns                   Disable reverse-DNS enrichment.
  --no-neighbor-cache        Ignore the scanner host's ARP/neighbor cache.
  --probe-timeout-ms <n>     Per-signal timeout. Default: 600.
  --network-concurrency <n>  Concurrent host probes. Default: 32; maximum: 256.
  --max-hosts <n>            Authorized address ceiling. Default: 4,096; hard maximum: 65,536.
  --max-probes-per-second <n>
                             Global host-start rate. Default: 64.
  --network-history-dir <p>  Inventory history used for automatic change detection.
  --no-network-history       Disable network inventory history/diff.
  --network-history-retain <n>
                             Keep newest n network snapshots. Default: 30; 0 = unlimited.

Local options (Windows/Linux):
  --root <path>              Scan root; repeat for multiple roots.
                             Linux defaults: existing /home, /srv, /opt, /var/www, /var/lib, /etc.
                             Windows defaults: ready fixed drives.
  --manifest <path>          Output manifest. Default: ./discovery-manifest.json
  --cross-filesystems        Linux only: descend into child mount points. Default: off.
  --include-system-mounts    Linux only: allow normally excluded virtual/runtime trees.
                             Default excludes /proc, /sys, /dev, /run and container overlay/runtime layers.

Authorized Windows SMB Remote Discover:
  --host <hostname|IPv4>     Explicit remote host; repeat for multiple hosts.
  --hosts-file <path>        Explicit host allowlist file. No CIDR/range/wildcard discovery.
  --remote-share <name>      Explicit SMB share; repeat. There is NO implicit C$ default.
  --username <user>          DOMAIN\\user, user@domain, or suitable local-account identity.
  --password-stdin           Read exactly one password line from stdin instead of hidden prompt.
  --host-delay-ms <n>        Delay between remote authentication attempts. Default: 250.

Authorized Linux SSH/SFTP Remote Discover (Windows or Linux scanner):
  --linux-host <host|IP>     Explicit Linux SSH host; repeat for multiple hosts. No CIDR/ranges/wildcards.
  --linux-hosts-file <path>  Explicit allowlist. Format: HOST|/root1;/root2|SHA256_FINGERPRINT
  --linux-root <path>        Explicit absolute Linux root; repeat. Defaults: /home /srv /opt /var/www /var/lib /etc.
  --linux-username <user>    SSH/SFTP user. root is accepted when intentionally authorized by the server owner.
  --linux-password-stdin     Read one Linux SSH password line from stdin instead of hidden prompt.
  --ssh-key <path>           Authenticate with an SSH private key instead of a password.
  --ssh-key-passphrase-stdin Read an encrypted-key passphrase from stdin.
  --ssh-key-passphrase-prompt
                             Prompt without echo for an encrypted-key passphrase.
  --ssh-port <n>             SSH port. Default: 22.
  --ssh-timeout-seconds <n>  SFTP operation timeout. Default: 30.
  --ssh-host-key-sha256 <fp> Expected SHA-256 host-key fingerprint for direct host(s).
  --ssh-known-hosts <path>   SmartBackupDiscovery host-key store. Default: ~/.smartbackupdiscovery/ssh-known-hosts.json
  --ssh-trust-on-first-use   Explicitly accept/store an unknown host key on first connection; later mismatches fail closed.

Linux behavior:
  - The net10.0 build also runs locally on Linux with the same DiscoverOnly engine.
  - Remote Linux mode uses SFTP directory/file metadata only: no shell command is executed and no remote file is downloaded.
  - Linux paths remain case-sensitive in manifests/history/gap analysis, including sftp:// paths.
  - Standard JVM layouts such as src/main/java use the project fast path remotely as well.
  - Important /etc configuration is reported as Must-Copy metadata.
  - Standard PostgreSQL/MySQL/MariaDB/Redis/libvirt/container-volume locations are logical application-aware backup sets.
  - SFTP does not expose reliable filesystem device/mount identity, so --cross-filesystems cannot prove mount-boundary isolation remotely;
    virtual/runtime trees such as /proc, /sys, /dev, /run and container overlay storage are still excluded by default.

Customer/reporting options:
  --backup-inventory <path>  JSON/CSV/TXT list of paths covered by the existing backup product.
  --history-dir <path>       Manifest history directory. Default: .sbd-history beside manifest.
  --no-history               Do not save history snapshot or auto-compare.
  --history-retain <n>       Keep newest n snapshots. Default: 30; 0 = unlimited.
  --report-dir <path>        Management report directory. Default: reports beside manifest.
  --no-report                Do not generate HTML/PDF management reports.
  --privacy-mode             Mask intermediate path components in management reports.

Inspection/resource options:
  --no-office-protection-scan
  --no-content-scan          Compatibility alias for the option above.
  --content-profile <mode>   balanced (default) or deep.
  --max-cpu-percent <n>      Adaptive CPU ceiling. Default: 75.
  --network-limit-mbps <n>   Global UNC inspection bandwidth ceiling. Default: 80; 0 = unlimited.
  --per-host-network-limit-mbps <n>
                             Per UNC host inspection ceiling. Default: 40; 0 = unlimited.
  --io-buffer-kib <n>        General I/O buffer policy. Default: 256.
  --max-adaptive-delay-ms <n>
                             Maximum dynamic per-file delay when CPU is busy. Default: 80.
  --max-files <n>            Traversal file ceiling. Default: 5,000,000.
  --max-directories <n>      Traversal directory ceiling. Default: 1,000,000.
  --max-depth <n>            Traversal depth ceiling. Default: 128.
  --no-checkpoint            Disable scan-progress JSONL checkpoint.
  --help                     Show this help.

Examples:
  # Automatic inventory of connected private IPv4 networks
  SmartBackupDiscovery.exe network-discover

  # Explicit authorized scope with an exclusion
  SmartBackupDiscovery.exe network-discover --cidr 192.168.10.0/24 --exclude-cidr 192.168.10.1/32 --authorized-scope

  # Linux
  ./SmartBackupDiscovery discover --root /srv --root /etc
  ./SmartBackupDiscovery discover --root /home --backup-inventory ./backup-covered.json

  # Windows
  SmartBackupDiscovery.exe
  SmartBackupDiscovery.exe discover --root D:\\ --backup-inventory .\\backup-covered.json
  SmartBackupDiscovery.exe discover --hosts-file .\\machines.txt --remote-share Data --username "CONTOSO\\backupscan"

Discover-only security boundaries:
  - network-discover is a separate inventory step. It never authenticates, enumerates shares, or starts a file scan.
  - Automatic scope is limited to connected RFC1918 IPv4 networks. Explicit CIDRs require --authorized-scope and must remain private.
  - Inventory probes are bounded by host, concurrency, rate, timeout, CPU and network limits.
  - Remote Windows file targets and shares remain explicit after inventory review; there is no automatic share enumeration.
  - Credentials establish temporary Windows SMB/WNet sessions only; passwords are not written to arguments, logs, manifest, history, or reports.
  - Linux mode does not execute SSH commands or crawl the network; it scans only local/explicitly mounted roots.
  - No discovered file is copied, moved, uploaded, deleted, modified, decrypted, or backed up by this program.
  - No document/source contents are searched for passwords, tokens, API keys, credentials, or connection strings.
  - Office inspection checks structural protection/encryption signals only and stores no document text.
""");
    }

}
