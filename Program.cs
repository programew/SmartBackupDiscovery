namespace SmartBackupDiscovery;

public static class Program
{
    public static int Main(string[] args)
    {
        try
        {
            if (args.Length == 0) return RunGui();
            return args[0].ToLowerInvariant() switch
            {
                "discover" => RunDiscover(args[1..]),
                "report" => RunReport(args[1..]),
                "compare" => RunCompare(args[1..]),
                "selftest" => SelfTest.Run(),
                "gui" => RunGui(),
                "help" or "--help" or "-h" => PrintHelp(),
                _ => Unknown(args[0])
            };
        }
        catch (Exception ex) { Console.Error.WriteLine(ex.Message); return 2; }
    }

    private static int RunGui()
    {
#if WINDOWS_BUILD
        System.Windows.Forms.ApplicationConfiguration.Initialize();
        System.Windows.Forms.Application.Run(new DashboardForm());
        return 0;
#else
        Console.Error.WriteLine("GUI is available in the net10.0-windows build. Use 'discover --help' on this platform.");
        return 2;
#endif
    }

    private static int Unknown(string command) { Console.Error.WriteLine($"Unknown command: {command}"); PrintHelp(); return 2; }

    private static int RunDiscover(string[] args)
    {
        if (Has(args, "--help")) { PrintHelp(); return 0; }
        string manifestPath = Path.GetFullPath(Get(args, "--manifest") ?? "discovery-manifest.json");
        var roots = GetMany(args, "--root").Select(Path.GetFullPath).ToList();
        var remoteHosts = GetMany(args, "--host");
        string? hostsFile = Get(args, "--hosts-file");
        var remoteShares = GetMany(args, "--remote-share");
        string? username = Get(args, "--username");
        bool passwordStdin = Has(args, "--password-stdin");

        var linuxHosts = GetMany(args, "--linux-host");
        string? linuxHostsFile = Get(args, "--linux-hosts-file");
        var linuxRoots = GetMany(args, "--linux-root");
        string? linuxUsername = Get(args, "--linux-username");
        bool linuxPasswordStdin = Has(args, "--linux-password-stdin");
        string? sshKey = Get(args, "--ssh-key");
        string? sshFingerprint = Get(args, "--ssh-host-key-sha256");
        string knownHosts = Get(args, "--ssh-known-hosts") ?? SshKnownHostsStore.GetDefaultPath();
        int sshPort = Int(args, "--ssh-port", 22, 1, 65535);
        int sshTimeout = Int(args, "--ssh-timeout-seconds", 30, 3, 600);
        bool tofu = Has(args, "--ssh-trust-on-first-use");

        var resource = new ResourcePolicy(
            Double(args, "--max-cpu", 75, 5, 100),
            Double(args, "--network-mbps", 80, 0, 100000),
            Double(args, "--per-host-mbps", 40, 0, 100000),
            Int(args, "--io-buffer-kib", 256, 32, 4096),
            Int(args, "--max-adaptive-delay-ms", 80, 0, 5000));
        var limits = new TraversalLimits(Long(args, "--max-files", 5_000_000, 1, long.MaxValue), Long(args, "--max-directories", 1_000_000, 1, long.MaxValue), Int(args, "--max-depth", 128, 1, 4096));
        var platform = new PlatformTraversalOptions(Has(args, "--cross-filesystems"), Has(args, "--include-system-mounts"));
        ContentInspectionProfile profile = (Get(args, "--profile") ?? "balanced").Equals("deep", StringComparison.OrdinalIgnoreCase) ? ContentInspectionProfile.Deep : ContentInspectionProfile.Balanced;
        bool inspectOffice = !Has(args, "--no-office-protection");

        using var smb = new AuthorizedRemoteAccess();
        var smbReports = new List<RemoteTargetReport>();
        var preErrors = new List<string>();
        if (remoteHosts.Count > 0 || !string.IsNullOrWhiteSpace(hostsFile))
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Credentialed SMB Authorized Remote Discover is Windows-only.");
            if (string.IsNullOrWhiteSpace(username)) throw new ArgumentException("--username is required for SMB remote discovery.");
            var targets = AuthorizedRemoteAccess.LoadTargets(remoteHosts, hostsFile, remoteShares);
            string password = passwordStdin ? AuthorizedRemoteAccess.ReadPasswordFromStdin() : AuthorizedRemoteAccess.ReadPasswordInteractively();
            RemoteAccessResult access = smb.Connect(targets, username, password, Int(args, "--host-delay-ms", 0, 0, 600000));
            roots.AddRange(access.Roots); smbReports.AddRange(access.Reports); preErrors.AddRange(access.Errors);
        }

        bool linuxRequested = linuxHosts.Count > 0 || !string.IsNullOrWhiteSpace(linuxHostsFile);
        if (roots.Count == 0 && !linuxRequested) roots.AddRange(PlatformScanPolicy.GetDefaultRoots());
        roots = roots.Distinct(PathRules.Comparer).ToList();

        DiscoveryManifest manifest = new DiscoveryEngine().Discover(
            roots, inspectOffice, profile, resource, limits,
            p => Console.Write($"\rFiles {p.FilesSeen:n0}  dirs {p.DirectoriesVisited:n0}  candidates {p.CandidatesFound:n0}   "),
            null, smbReports, preErrors, platform);
        Console.WriteLine();

        if (linuxRequested)
        {
            if (string.IsNullOrWhiteSpace(linuxUsername)) throw new ArgumentException("--linux-username is required for Linux SFTP discovery.");
            var targets = RemoteLinuxSftpDiscovery.LoadTargets(linuxHosts, linuxHostsFile, linuxRoots, sshPort, sshFingerprint);
            string? password = null, passphrase = null;
            if (string.IsNullOrWhiteSpace(sshKey)) password = linuxPasswordStdin ? AuthorizedRemoteAccess.ReadPasswordFromStdin() : AuthorizedRemoteAccess.ReadPasswordInteractively("Linux SSH password");
            else if (Has(args, "--ssh-key-passphrase-stdin")) passphrase = AuthorizedRemoteAccess.ReadPasswordFromStdin();
            else if (Has(args, "--ssh-key-passphrase-prompt")) passphrase = AuthorizedRemoteAccess.ReadPasswordInteractively("SSH key passphrase");
            var cred = new LinuxSftpCredential(linuxUsername, password, sshKey, passphrase);
            RemoteLinuxScanResult remote = new RemoteLinuxSftpDiscovery().Scan(targets, cred, limits, platform, knownHosts, tofu, sshTimeout);
            manifest = DiscoveryManifestMerger.WithRemoteLinux(manifest, remote);
        }

        if (Get(args, "--backup-inventory") is { } inventoryPath)
        {
            BackupInventory inv = BackupGapAnalyzer.LoadInventory(inventoryPath);
            manifest.BackupGap = BackupGapAnalyzer.Analyze(manifest, inv);
        }

        string historyDir = Get(args, "--history-dir") ?? ManifestHistoryService.GetDefaultHistoryDirectory(manifestPath);
        if (!Has(args, "--no-history"))
        {
            PreviousManifestResult? previous = ManifestHistoryService.FindPrevious(manifestPath, historyDir, manifest);
            manifest.Diff = previous is null ? ManifestDiffService.NoPrevious() : ManifestDiffService.Compare(previous.Manifest, manifest, previous.ReferencePath);
        }
        manifest.Readiness = BackupReadinessCalculator.Calculate(manifest, manifest.BackupGap);
        ManifestWriter.WriteDiscovery(manifestPath, manifest);
        if (!Has(args, "--no-history")) { ManifestHistoryService.SaveSnapshot(historyDir, manifest); ManifestHistoryService.PruneSnapshots(historyDir, Int(args, "--history-retain", 30, 1, 10000)); }
        if (Get(args, "--report-dir") is { } reportDir) ManagementReportWriter.Write(reportDir, manifestPath, manifest, Has(args, "--privacy-mode"));
        PrintSummary(manifest, manifestPath);
        return 0;
    }

    private static int RunReport(string[] args)
    {
        string manifestPath = Path.GetFullPath(Get(args, "--manifest") ?? RequirePositional(args, 0, "manifest path"));
        string output = Get(args, "--output-dir") ?? Path.Combine(Path.GetDirectoryName(manifestPath) ?? Environment.CurrentDirectory, "report");
        DiscoveryManifest manifest = ManifestReader.Read(manifestPath);
        manifest.Readiness ??= BackupReadinessCalculator.Calculate(manifest, manifest.BackupGap);
        ManagementReportArtifacts artifacts = ManagementReportWriter.Write(output, manifestPath, manifest, Has(args, "--privacy-mode"));
        Console.WriteLine(artifacts.HtmlPath); Console.WriteLine(artifacts.PdfPath); return 0;
    }

    private static int RunCompare(string[] args)
    {
        if (args.Length < 2) throw new ArgumentException("compare requires <previous-manifest> <current-manifest>.");
        var previous = ManifestReader.Read(args[0]); var current = ManifestReader.Read(args[1]);
        ScanDiffSummary diff = ManifestDiffService.Compare(previous, current, args[0]);
        Console.WriteLine($"Added {diff.AddedCount}, changed {diff.ChangedCount}, removed {diff.RemovedCount}; +{diff.AddedBytes:n0} bytes / -{diff.RemovedBytes:n0} bytes");
        foreach (var c in diff.TopChanges.Take(50)) Console.WriteLine($"{c.ChangeType,-8} {c.Path}");
        return 0;
    }

    private static void PrintSummary(DiscoveryManifest m, string path)
    {
        Console.WriteLine($"Manifest: {path}");
        Console.WriteLine($"Candidates: {m.Candidates.Count:n0} / {SizeMath.SumCandidateBytes(m.Candidates):n0} bytes");
        Console.WriteLine($"Must-copy estimate: {m.MustCopyVolume.FileCount:n0} files / {m.MustCopyVolume.EstimatedBytes:n0} bytes");
        Console.WriteLine($"Projects: {m.ProjectVolumes.Count:n0}; JVM projects: {m.Performance.JvmProjectsDetected:n0}");
        Console.WriteLine($"Fast-path files: {m.Performance.ProjectFastPathFiles:n0}; signature probes avoided: {m.Performance.SignatureProbesAvoided:n0}");
        if (m.Readiness is not null) Console.WriteLine($"Backup readiness: {m.Readiness.Score}/100 ({m.Readiness.Grade}), confidence {m.Readiness.Confidence}");
    }

    private static string? Get(string[] a, string n) { for (int i = 0; i < a.Length - 1; i++) if (a[i].Equals(n, StringComparison.OrdinalIgnoreCase)) return a[i + 1]; return null; }
    private static List<string> GetMany(string[] a, string n) { var r = new List<string>(); for (int i = 0; i < a.Length - 1; i++) if (a[i].Equals(n, StringComparison.OrdinalIgnoreCase)) r.Add(a[i + 1]); return r; }
    private static bool Has(string[] a, string n) => a.Any(x => x.Equals(n, StringComparison.OrdinalIgnoreCase));
    private static int Int(string[] a, string n, int f, int min, int max) => Get(a, n) is { } v && int.TryParse(v, out int x) ? Math.Clamp(x, min, max) : f;
    private static long Long(string[] a, string n, long f, long min, long max) => Get(a, n) is { } v && long.TryParse(v, out long x) ? Math.Clamp(x, min, max) : f;
    private static double Double(string[] a, string n, double f, double min, double max) => Get(a, n) is { } v && double.TryParse(v, out double x) ? Math.Clamp(x, min, max) : f;
    private static string RequirePositional(string[] a, int i, string label) => a.Length > i && !a[i].StartsWith('-') ? a[i] : throw new ArgumentException($"Missing {label}.");

    private static int PrintHelp()
    {
        Console.WriteLine("SmartBackupDiscovery 3.3 (.NET 10) - Discover-only backup readiness inventory\n\nCommands:\n  discover [options]\n  report <manifest> [--output-dir DIR] [--privacy-mode]\n  compare <previous> <current>\n  selftest\n  gui (Windows build)\n\nLocal:\n  --root PATH (repeatable)  --manifest FILE  --profile balanced|deep\n  --max-cpu N --network-mbps N --per-host-mbps N --max-files N --max-directories N --max-depth N\n  --cross-filesystems --include-system-mounts --no-office-protection\n\nAuthorized Windows SMB:\n  --host HOST / --hosts-file FILE  --remote-share SHARE  --username USER [--password-stdin]\n\nAuthorized Linux SFTP (metadata-only):\n  --linux-host HOST / --linux-hosts-file FILE  --linux-root /PATH  --linux-username USER\n  [--linux-password-stdin] [--ssh-key FILE] [--ssh-key-passphrase-prompt|--ssh-key-passphrase-stdin]\n  [--ssh-port 22] [--ssh-host-key-sha256 FP] [--ssh-known-hosts FILE] [--ssh-trust-on-first-use]\n\nAssessment/reporting:\n  --backup-inventory FILE --history-dir DIR --history-retain N --no-history --report-dir DIR --privacy-mode");
        return 0;
    }
}
