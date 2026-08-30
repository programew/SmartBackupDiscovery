using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Renci.SshNet;
using Renci.SshNet.Sftp;

namespace SmartBackupDiscovery;

public sealed record LinuxRemoteTargetSpec(string Host, int Port, IReadOnlyList<string> Roots, string? HostKeySha256);

public sealed record LinuxSftpCredential(string Username, string? Password, string? PrivateKeyPath, string? PrivateKeyPassphrase)
{
    public bool UsesPrivateKey => !string.IsNullOrWhiteSpace(PrivateKeyPath);
    public string AuthenticationMode => UsesPrivateKey ? "SshPrivateKey" : "SshPassword";
}

public sealed record RemoteLinuxScanResult(
    IReadOnlyList<SourceDescriptor> Sources,
    IReadOnlyList<RemoteLinuxTargetReport> Reports,
    IReadOnlyList<FileCandidate> Candidates,
    IReadOnlyList<BackupSet> BackupSets,
    IReadOnlyList<string> Errors,
    ScanCoverage Coverage,
    IReadOnlyList<ProjectVolumeStat> ProjectVolumes,
    ScanPerformanceSummary Performance,
    MustCopyVolumeSummary MustCopyVolume)
{
    public static RemoteLinuxScanResult Empty { get; } = new(
        Array.Empty<SourceDescriptor>(), Array.Empty<RemoteLinuxTargetReport>(), Array.Empty<FileCandidate>(),
        Array.Empty<BackupSet>(), Array.Empty<string>(), ScanCoverage.Empty, Array.Empty<ProjectVolumeStat>(),
        ScanPerformanceSummary.Empty, MustCopyVolumeSummary.Empty);
}

public sealed class RemoteLinuxSftpDiscovery
{
    private const int MaxRecordedErrors = 5000;
    private static readonly string[] DefaultLinuxRoots = ["/home", "/srv", "/opt", "/var/www", "/var/lib", "/etc"];
    private static readonly string[] SystemVirtualRoots = ["/proc", "/sys", "/dev", "/run"];
    private static readonly string[] ContainerRuntimeRoots = ["/var/lib/docker/overlay2", "/var/lib/containers/storage/overlay", "/var/lib/containers/storage/overlay-containers"];

    public RemoteLinuxScanResult Scan(
        IReadOnlyList<LinuxRemoteTargetSpec> targets,
        LinuxSftpCredential credential,
        TraversalLimits limits,
        PlatformTraversalOptions traversalOptions,
        string knownHostsPath,
        bool trustOnFirstUse,
        int operationTimeoutSeconds,
        Action<ScanProgress>? progress = null,
        Action<FileCandidate>? onCandidate = null)
    {
        if (targets.Count == 0) return RemoteLinuxScanResult.Empty;
        if (string.IsNullOrWhiteSpace(credential.Username)) throw new ArgumentException("Linux SSH username cannot be empty.");
        if (!credential.UsesPrivateKey && credential.Password is null) throw new ArgumentException("Linux SSH password is required when no private key is supplied.");
        if (credential.UsesPrivateKey && !File.Exists(Path.GetFullPath(credential.PrivateKeyPath!))) throw new FileNotFoundException("SSH private key was not found.", credential.PrivateKeyPath);

        var knownHosts = SshKnownHostsStore.Load(knownHostsPath);
        var sources = new List<SourceDescriptor>();
        var reports = new List<RemoteLinuxTargetReport>();
        var candidates = new Dictionary<string, FileCandidate>(StringComparer.Ordinal);
        var backupSets = new List<BackupSet>();
        var errors = new List<string>();
        var coverageRoots = new List<RootCoverage>();
        var projectVolumes = new List<ProjectVolumeStat>();

        long totalDirs = 0, totalFiles = 0, totalCandidates = 0, totalPolicySkipped = 0, totalSymlinkDirs = 0, totalSymlinkFiles = 0;
        long projectFastPathFiles = 0, signatureProbesAvoided = 0, generatedDirsSkipped = 0, linuxPolicySkipped = 0;
        int jvmProjectsDetected = 0;

        foreach (LinuxRemoteTargetSpec target in targets)
        {
            ResolveHost(target.Host, out string hostName, out var v4, out var v6);
            string? observedFingerprint = null;
            bool acceptedNewHostKey = false;
            string? expectedFingerprint = NormalizeFingerprint(target.HostKeySha256);
            if (expectedFingerprint is null) knownHosts.TryGet(target.Host, target.Port, out expectedFingerprint);

            var rootReports = new List<RemoteLinuxRootAccessReport>();
            RemoteAuthenticationStatus authStatus = RemoteAuthenticationStatus.Failed;
            PrivateKeyFile? privateKey = null;
            SftpClient? client = null;

            try
            {
                client = CreateClient(target, credential, ref privateKey);
                client.OperationTimeout = TimeSpan.FromSeconds(operationTimeoutSeconds);
                client.KeepAliveInterval = TimeSpan.FromSeconds(30);
                client.HostKeyReceived += (_, e) =>
                {
                    observedFingerprint = NormalizeFingerprint(e.FingerPrintSHA256);
                    if (expectedFingerprint is not null)
                    {
                        e.CanTrust = string.Equals(observedFingerprint, expectedFingerprint, StringComparison.Ordinal);
                        return;
                    }
                    if (trustOnFirstUse)
                    {
                        e.CanTrust = true;
                        acceptedNewHostKey = true;
                        return;
                    }
                    e.CanTrust = false;
                };

                client.Connect();
                authStatus = RemoteAuthenticationStatus.Succeeded;
                if (acceptedNewHostKey && observedFingerprint is not null)
                {
                    knownHosts.Set(target.Host, target.Port, observedFingerprint);
                    knownHosts.Save();
                    expectedFingerprint = observedFingerprint;
                }

                foreach (string requestedRoot in target.Roots)
                {
                    string remoteRoot = RemoteLinuxPath.NormalizeAbsolute(requestedRoot);
                    string sourceRoot = RemoteLinuxPath.ToSftpUri(target.Host, target.Port, remoteRoot);
                    string sourceId = $"sftp:{SourceIdentityProvider.Sanitize(target.Host)}:{target.Port}:{StableId.Hash12(remoteRoot)}";
                    sources.Add(new SourceDescriptor(sourceId, SourceKind.LinuxSftp, sourceRoot, target.Host, null, remoteRoot));

                    RemoteRootScan rootScan = ScanRoot(client, target, remoteRoot, sourceId, limits, traversalOptions, candidates, errors, progress, onCandidate);
                    coverageRoots.Add(rootScan.Coverage);
                    rootReports.Add(new RemoteLinuxRootAccessReport(sourceRoot, rootScan.Coverage.Exists, rootScan.Coverage.DirectoriesVisited, rootScan.Coverage.FilesSeen, rootScan.Coverage.CandidatesFound, rootScan.Error));

                    totalDirs = SizeMath.AddSaturating(totalDirs, rootScan.Coverage.DirectoriesVisited);
                    totalFiles = SizeMath.AddSaturating(totalFiles, rootScan.Coverage.FilesSeen);
                    totalCandidates = SizeMath.AddSaturating(totalCandidates, rootScan.Coverage.CandidatesFound);
                    totalPolicySkipped = SizeMath.AddSaturating(totalPolicySkipped, rootScan.Coverage.PolicyDirectoriesSkipped);
                    totalSymlinkDirs = SizeMath.AddSaturating(totalSymlinkDirs, rootScan.Coverage.ReparseDirectoriesSkipped);
                    totalSymlinkFiles = SizeMath.AddSaturating(totalSymlinkFiles, rootScan.Coverage.ReparseFilesSkipped);
                    projectFastPathFiles = SizeMath.AddSaturating(projectFastPathFiles, rootScan.ProjectFastPathFiles);
                    signatureProbesAvoided = SizeMath.AddSaturating(signatureProbesAvoided, rootScan.SignatureProbesAvoided);
                    generatedDirsSkipped = SizeMath.AddSaturating(generatedDirsSkipped, rootScan.GeneratedDirectoriesSkipped);
                    linuxPolicySkipped = SizeMath.AddSaturating(linuxPolicySkipped, rootScan.LinuxPolicyDirectoriesSkipped);
                    jvmProjectsDetected += rootScan.JvmProjectsDetected;
                    projectVolumes.AddRange(rootScan.ProjectVolumes);
                    backupSets.AddRange(rootScan.ProjectSets);
                    backupSets.AddRange(rootScan.ServiceSets);
                }

                if (rootReports.Count > 0 && rootReports.Any(x => !x.Accessible || x.Error is not null)) authStatus = rootReports.All(x => !x.Accessible) ? RemoteAuthenticationStatus.Failed : RemoteAuthenticationStatus.Partial;
            }
            catch (Exception ex)
            {
                string detail = string.Empty;
                if (observedFingerprint is not null && expectedFingerprint is null && !trustOnFirstUse)
                    detail = $" Unknown SSH host key. Observed SHA256:{observedFingerprint}. Re-run with --ssh-host-key-sha256 {observedFingerprint} for a single host, put the fingerprint in the Linux hosts file, or explicitly use --ssh-trust-on-first-use.";
                else if (observedFingerprint is not null && expectedFingerprint is not null && !string.Equals(observedFingerprint, expectedFingerprint, StringComparison.Ordinal))
                    detail = $" SSH host-key mismatch. Expected SHA256:{expectedFingerprint}, observed SHA256:{observedFingerprint}. Connection was rejected.";
                AddError(errors, $"Linux SFTP connection failed for {target.Host}:{target.Port}: {ex.Message}.{detail}");
                authStatus = RemoteAuthenticationStatus.Failed;
                if (rootReports.Count == 0)
                    foreach (string root in target.Roots) rootReports.Add(new RemoteLinuxRootAccessReport(RemoteLinuxPath.ToSftpUri(target.Host, target.Port, root), false, 0, 0, 0, ex.Message));
            }
            finally
            {
                try { client?.Disconnect(); } catch { }
                client?.Dispose();
                privateKey?.Dispose();
            }

            reports.Add(new RemoteLinuxTargetReport(target.Host, hostName, target.Port, v4, v6, credential.AuthenticationMode, authStatus, observedFingerprint, rootReports));
        }

        backupSets.AddRange(BuildRemoteDatabaseSets(candidates.Values));
        var coverage = new ScanCoverage(coverageRoots, totalDirs, totalFiles, totalCandidates, totalPolicySkipped, totalSymlinkDirs, totalSymlinkFiles);
        var performance = new ScanPerformanceSummary(projectFastPathFiles, signatureProbesAvoided, jvmProjectsDetected, generatedDirsSkipped, linuxPolicySkipped, 0);
        MustCopyVolumeSummary mustCopy = CalculateMustCopy(projectVolumes, candidates.Values);
        return new RemoteLinuxScanResult(
            sources.DistinctBy(x => x.Id).ToArray(), reports,
            candidates.Values.OrderByDescending(x => x.Score).ThenBy(x => x.Path, StringComparer.Ordinal).ToArray(),
            backupSets.GroupBy(x => x.Id, StringComparer.OrdinalIgnoreCase).Select(x => x.First()).OrderByDescending(x => x.Score).ToArray(),
            errors, coverage,
            projectVolumes.GroupBy(x => x.Root, StringComparer.Ordinal).Select(g => new ProjectVolumeStat(g.Key, SumSaturating(g.Select(x => x.Files)), SumSaturating(g.Select(x => x.Bytes)), g.Any(x => x.JvmDetected))).ToArray(),
            performance, mustCopy);
    }

    public static IReadOnlyList<LinuxRemoteTargetSpec> LoadTargets(IEnumerable<string> directHosts, string? hostsFile, IReadOnlyList<string> defaultRoots, int defaultPort, string? defaultFingerprint)
    {
        var raw = new List<(string Host, IReadOnlyList<string>? Roots, string? Fingerprint)>();
        foreach (string host in directHosts) raw.Add((ValidateHost(host), null, NormalizeFingerprint(defaultFingerprint)));
        if (!string.IsNullOrWhiteSpace(hostsFile))
        {
            string path = Path.GetFullPath(hostsFile);
            foreach (string sourceLine in File.ReadLines(path))
            {
                string line = sourceLine.Trim();
                if (line.Length == 0 || line.StartsWith('#')) continue;
                string[] parts = line.Split('|', 3, StringSplitOptions.TrimEntries);
                string host = ValidateHost(parts[0]);
                IReadOnlyList<string>? roots = null;
                if (parts.Length >= 2 && !string.IsNullOrWhiteSpace(parts[1])) roots = parts[1].Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(RemoteLinuxPath.NormalizeAbsolute).Distinct(StringComparer.Ordinal).ToArray();
                string? fp = parts.Length >= 3 ? NormalizeFingerprint(parts[2]) : null;
                raw.Add((host, roots, fp));
            }
        }
        string[] normalizedDefaults = (defaultRoots.Count > 0 ? defaultRoots : DefaultLinuxRoots).Select(RemoteLinuxPath.NormalizeAbsolute).Distinct(StringComparer.Ordinal).ToArray();
        return raw.GroupBy(x => x.Host, StringComparer.OrdinalIgnoreCase).Select(group =>
        {
            string[] explicitRoots = group.Where(x => x.Roots is not null).SelectMany(x => x.Roots!).Distinct(StringComparer.Ordinal).ToArray();
            string[] roots = explicitRoots.Length > 0 ? explicitRoots : normalizedDefaults;
            string? fp = group.Select(x => x.Fingerprint).FirstOrDefault(x => !string.IsNullOrWhiteSpace(x)) ?? NormalizeFingerprint(defaultFingerprint);
            return new LinuxRemoteTargetSpec(group.Key, defaultPort, roots, fp);
        }).ToArray();
    }

    private static RemoteRootScan ScanRoot(
        SftpClient client, LinuxRemoteTargetSpec target, string remoteRoot, string sourceId,
        TraversalLimits limits, PlatformTraversalOptions traversalOptions,
        Dictionary<string, FileCandidate> allCandidates, List<string> errors,
        Action<ScanProgress>? progress, Action<FileCandidate>? onCandidate)
    {
        string sourceRoot = RemoteLinuxPath.ToSftpUri(target.Host, target.Port, remoteRoot);
        long dirs = 0, files = 0, found = 0, policySkipped = 0, symlinkDirs = 0, symlinkFiles = 0, rootErrors = 0;
        long projectFastPath = 0, signatureAvoided = 0, generatedSkipped = 0, linuxPolicySkipped = 0;
        int jvmProjects = 0;
        bool completed = true;
        string? rootError = null;
        var projectFiles = new Dictionary<string, long>(StringComparer.Ordinal);
        var projectBytes = new Dictionary<string, long>(StringComparer.Ordinal);
        var projectJvm = new HashSet<string>(StringComparer.Ordinal);
        var projectSets = new Dictionary<string, BackupSet>(StringComparer.Ordinal);
        var serviceSets = new Dictionary<string, BackupSet>(StringComparer.Ordinal);
        var stack = new Stack<(string Path, int Depth, string? ProjectRoot)>();
        var visited = new HashSet<string>(StringComparer.Ordinal);
        stack.Push((remoteRoot, 0, null));

        while (stack.Count > 0)
        {
            if (dirs >= limits.MaxDirectories || files >= limits.MaxFiles)
            {
                completed = false; rootErrors++; rootError = "Traversal budget reached; remaining remote paths were not scanned.";
                AddError(errors, $"{sourceRoot}: {rootError}"); break;
            }
            var (dir, depth, inheritedProjectRoot) = stack.Pop();
            if (!visited.Add(dir)) continue;
            if (depth > limits.MaxDepth)
            {
                completed = false; rootErrors++;
                AddError(errors, $"Maximum depth {limits.MaxDepth} exceeded under {RemoteLinuxPath.ToSftpUri(target.Host, target.Port, dir)}"); continue;
            }
            if (ShouldSkipRemoteDirectory(dir, traversalOptions, out _)) { policySkipped++; linuxPolicySkipped++; continue; }

            List<ISftpFile> entries;
            try { entries = client.ListDirectory(dir).Where(x => x.Name is not "." and not "..").ToList(); }
            catch (Exception ex)
            {
                completed = false; rootErrors++; if (depth == 0) rootError = ex.Message;
                AddError(errors, $"Cannot enumerate {RemoteLinuxPath.ToSftpUri(target.Host, target.Port, dir)}: {ex.Message}"); continue;
            }

            dirs++;
            string? currentProjectRoot = inheritedProjectRoot;
            if (currentProjectRoot is null)
            {
                if (entries.Any(x => (x.IsRegularFile || x.IsDirectory) && FileClassifier.IsProjectMarkerName(x.Name))) currentProjectRoot = dir;
                else if (TryInferJvmProjectRoot(dir, remoteRoot, entries, out string? inferred))
                {
                    currentProjectRoot = inferred; projectJvm.Add(inferred!); jvmProjects++;
                }
            }

            if (currentProjectRoot is not null && !projectSets.ContainsKey(currentProjectRoot))
            {
                string displayRoot = RemoteLinuxPath.ToSftpUri(target.Host, target.Port, currentProjectRoot);
                bool jvm = projectJvm.Contains(currentProjectRoot) || entries.Any(x => x.IsRegularFile && IsJvmMarker(x.Name));
                if (jvm && projectJvm.Add(currentProjectRoot)) jvmProjects++;
                projectSets[currentProjectRoot] = new BackupSet(
                    $"project:{StableId.Hash12(displayRoot)}", "Project", RemoteLinuxPath.GetName(currentProjectRoot), 140, BackupPriority.High,
                    new[] { displayRoot },
                    new[] { "Remote Linux project/source root detected from project markers or JVM source-tree structure", "SFTP metadata-only discovery; file content was not downloaded" },
                    new[] { sourceId });
            }

            AddServiceSetIfApplicable(dir, target, sourceId, serviceSets);

            foreach (ISftpFile entry in entries)
            {
                string child;
                try { child = RemoteLinuxPath.Combine(dir, entry.Name); } catch { continue; }
                if (entry.IsSymbolicLink) { if (entry.IsDirectory) symlinkDirs++; else symlinkFiles++; continue; }
                if (entry.IsDirectory)
                {
                    if (ShouldSkipRemoteDirectory(child, traversalOptions, out _)) { policySkipped++; linuxPolicySkipped++; continue; }
                    if (currentProjectRoot is not null && FileClassifier.ShouldSkipProjectDirectoryName(entry.Name)) { policySkipped++; generatedSkipped++; continue; }
                    stack.Push((child, depth + 1, currentProjectRoot));
                    continue;
                }
                if (!entry.IsRegularFile) continue;
                files++;
                long size = Math.Max(0, entry.Length);

                if (currentProjectRoot is not null)
                {
                    projectFastPath++;
                    if (!FileClassifier.WouldProbeSignature(entry.Name)) signatureAvoided++;
                    projectFiles[currentProjectRoot] = projectFiles.GetValueOrDefault(currentProjectRoot) + 1;
                    projectBytes[currentProjectRoot] = SaturatingAdd(projectBytes.GetValueOrDefault(currentProjectRoot), size);
                    if (!FileClassifier.IsProjectMarkerName(entry.Name)) continue;
                }

                LinuxFileHint? remoteHint = LinuxBackupHints.GetHintForRemotePath(child);
                if (LinuxBackupHints.IsMetadataOnlyRemotePath(child) && remoteHint?.MustInclude != true) continue;

                string displayPath = RemoteLinuxPath.ToSftpUri(target.Host, target.Port, child);
                FileCandidate candidate = FileClassifier.AnalyzeRemoteLinuxMetadata(displayPath, child, entry.Name, size, entry.LastWriteTimeUtc, sourceId);
                if (candidate.Priority == BackupPriority.Ignore) continue;
                allCandidates[displayPath] = candidate; found++; onCandidate?.Invoke(candidate);
                progress?.Invoke(new ScanProgress(files, dirs, found, displayPath, 0));
            }
        }

        var volumes = projectFiles.Select(pair => new ProjectVolumeStat(RemoteLinuxPath.ToSftpUri(target.Host, target.Port, pair.Key), pair.Value, projectBytes.GetValueOrDefault(pair.Key), projectJvm.Contains(pair.Key))).ToArray();
        return new RemoteRootScan(
            new RootCoverage(sourceRoot, dirs > 0, completed, dirs, files, found, policySkipped, symlinkDirs, symlinkFiles, rootErrors),
            projectFastPath, signatureAvoided, jvmProjects, generatedSkipped, linuxPolicySkipped,
            volumes, projectSets.Values.ToArray(), serviceSets.Values.ToArray(), rootError);
    }

    private static bool TryInferJvmProjectRoot(string dir, string scanRoot, IReadOnlyList<ISftpFile> entries, out string? projectRoot)
    {
        projectRoot = null;
        string p = RemoteLinuxPath.NormalizeAbsolute(dir);
        string[] suffixes = ["/src/main/java", "/src/test/java", "/src/main/kotlin", "/src/test/kotlin", "/src/main/scala", "/src/test/scala", "/src/main/groovy", "/src/test/groovy"];
        foreach (string suffix in suffixes)
        {
            if (!p.EndsWith(suffix, StringComparison.Ordinal)) continue;
            string candidate = p[..^suffix.Length]; if (candidate.Length == 0) candidate = "/";
            projectRoot = RemoteLinuxPath.IsSameOrUnder(candidate, scanRoot) ? candidate : scanRoot; return true;
        }
        if (p.EndsWith("/src", StringComparison.Ordinal) && entries.Any(x => x.IsDirectory && (x.Name.Equals("main", StringComparison.Ordinal) || x.Name.Equals("test", StringComparison.Ordinal))))
        {
            string? parent = RemoteLinuxPath.GetParent(p);
            if (parent is not null && RemoteLinuxPath.IsSameOrUnder(parent, scanRoot)) { projectRoot = parent; return true; }
        }
        if (!p.Equals(scanRoot, StringComparison.Ordinal)) return false;
        int jvmDirect = entries.Count(x => x.IsRegularFile && FileClassifier.IsJvmSourceFileName(x.Name));
        if (jvmDirect >= 5) { projectRoot = p; return true; }
        bool sourceLikeName = new[] { "src", "source", "sources", "java", "code", "repo", "repos", "repository", "workspace", "project", "projects" }
            .Any(term => RemoteLinuxPath.GetName(p).Contains(term, StringComparison.OrdinalIgnoreCase));
        bool packageRoot = entries.Any(x => x.IsDirectory && (x.Name.Equals("com", StringComparison.OrdinalIgnoreCase) || x.Name.Equals("org", StringComparison.OrdinalIgnoreCase) || x.Name.Equals("net", StringComparison.OrdinalIgnoreCase) || x.Name.Equals("io", StringComparison.OrdinalIgnoreCase)));
        if (sourceLikeName && packageRoot) { projectRoot = p; return true; }
        return false;
    }

    private static bool IsJvmMarker(string name)
    {
        string n = name.ToLowerInvariant();
        return n is "pom.xml" or "build.gradle" or "build.gradle.kts" or "settings.gradle" or "settings.gradle.kts" or "gradle.properties" or "gradlew" or "mvnw" or "build.xml" or "ivy.xml" or "androidmanifest.xml";
    }

    private static void AddServiceSetIfApplicable(string dir, LinuxRemoteTargetSpec target, string sourceId, Dictionary<string, BackupSet> result)
    {
        foreach (var service in LinuxServiceCatalog.Services)
        {
            if (!dir.Equals(service.Path, StringComparison.Ordinal)) continue;
            string display = RemoteLinuxPath.ToSftpUri(target.Host, target.Port, dir);
            string id = $"linux-service:{StableId.Hash12(display)}";
            result.TryAdd(id, new BackupSet(id, "LinuxServiceData", service.Name, 190, BackupPriority.Critical,
                new[] { display },
                new[] { "Persistent Linux service data detected in a standard service location", service.BackupGuidance, "Remote SFTP discovery is metadata-only; use an application-aware backup or consistent snapshot where required" },
                new[] { sourceId }));
        }
    }

    private static bool ShouldSkipRemoteDirectory(string path, PlatformTraversalOptions options, out string reason)
    {
        string p = RemoteLinuxPath.NormalizeAbsolute(path);
        if (!options.IncludeSystemMounts && SystemVirtualRoots.Any(root => RemoteLinuxPath.IsSameOrUnder(p, root))) { reason = "system virtual/runtime filesystem"; return true; }
        if (!options.IncludeSystemMounts && ContainerRuntimeRoots.Any(root => RemoteLinuxPath.IsSameOrUnder(p, root))) { reason = "container runtime/overlay storage"; return true; }
        reason = string.Empty; return false;
    }

    private static SftpClient CreateClient(LinuxRemoteTargetSpec target, LinuxSftpCredential credential, ref PrivateKeyFile? privateKey)
    {
        if (credential.UsesPrivateKey)
        {
            string keyPath = Path.GetFullPath(credential.PrivateKeyPath!);
            privateKey = credential.PrivateKeyPassphrase is null ? new PrivateKeyFile(keyPath) : new PrivateKeyFile(keyPath, credential.PrivateKeyPassphrase);
            return new SftpClient(target.Host, target.Port, credential.Username, privateKey);
        }
        return new SftpClient(target.Host, target.Port, credential.Username, credential.Password!);
    }

    private static MustCopyVolumeSummary CalculateMustCopy(IEnumerable<ProjectVolumeStat> projectVolumes, IEnumerable<FileCandidate> candidates)
    {
        ProjectVolumeStat[] projects = projectVolumes.ToArray();
        long projectFiles = SumSaturating(projects.Select(x => x.Files));
        long projectBytes = SumSaturating(projects.Select(x => x.Bytes));
        string[] projectRoots = projects.Select(x => x.Root).ToArray();
        FileCandidate[] standalone = candidates.Where(x => x.MustInclude || x.Priority == BackupPriority.Critical)
            .Where(x => !projectRoots.Any(root => RemoteLinuxPath.IsSameOrUnderSftpUri(x.Path, root))).ToArray();
        long standaloneBytes = SumSaturating(standalone.Select(x => x.Size));
        return new MustCopyVolumeSummary(
            SaturatingAdd(projectFiles, standalone.LongLength), SaturatingAdd(projectBytes, standaloneBytes),
            projectFiles, projectBytes, standalone.LongLength, standaloneBytes,
            standalone.Count(x => x.MustInclude), SumSaturating(standalone.Where(x => x.MustInclude).Select(x => x.Size)), 0, 0,
            "Remote Linux SFTP estimate: detected project source trees excluding generated/dependency directories, plus standalone Critical/MustInclude metadata candidates. File content was not downloaded; live service data is represented as application-aware logical backup sets.");
    }

    private static IReadOnlyList<BackupSet> BuildRemoteDatabaseSets(IEnumerable<FileCandidate> candidates)
    {
        return candidates.Where(x => x.Category == FileCategory.Database)
            .GroupBy(x => RemoteLinuxPath.TrySplitSftpUri(x.Path, out string host, out int port, out string path)
                ? RemoteLinuxPath.ToSftpUri(host, port, RemoteLinuxPath.GetParent(path) ?? "/") : x.Path, StringComparer.Ordinal)
            .Select(group =>
            {
                string name = RemoteLinuxPath.TrySplitSftpUri(group.Key, out _, out _, out string path) ? RemoteLinuxPath.GetName(path) : "database";
                return new BackupSet(
                    $"database:{StableId.Hash12(group.Key)}", "DatabaseFiles", name, Math.Max(180, group.Max(x => x.Score)), BackupPriority.Critical,
                    group.Select(x => x.Path).ToArray(),
                    new[] { "Database files detected from remote Linux file metadata/type", "SFTP metadata-only discovery; file content was not downloaded" },
                    group.Select(x => x.SourceId).Distinct(StringComparer.OrdinalIgnoreCase).ToArray());
            }).ToArray();
    }

    private static string ValidateHost(string input)
    {
        string host = input.Trim();
        if (string.IsNullOrWhiteSpace(host)) throw new ArgumentException("Linux SSH host cannot be empty.");
        if (host.IndexOfAny(['*', '?', '/', '\\', ',', ';', '|']) >= 0 || host.Contains("..", StringComparison.Ordinal))
            throw new ArgumentException($"Linux SSH host '{input}' is not one explicit hostname/IP. Wildcards, CIDR/ranges, paths and lists are not accepted.");
        if (host.Contains('/') || host.Contains(' ')) throw new ArgumentException($"Invalid Linux SSH host: {input}");
        if (host.Contains(':') && !IPAddress.TryParse(host, out _)) throw new ArgumentException($"Linux SSH host '{input}' contains an invalid colon/port form. Use --ssh-port separately.");
        return host.Trim('[', ']');
    }

    internal static string? NormalizeFingerprint(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        string fp = value.Trim(); if (fp.StartsWith("SHA256:", StringComparison.OrdinalIgnoreCase)) fp = fp[7..]; fp = fp.TrimEnd('=');
        if (fp.Length < 20 || fp.Any(ch => !(char.IsLetterOrDigit(ch) || ch is '+' or '/' or '-' or '_')))
            throw new ArgumentException("SSH host-key fingerprint must be a SHA-256 base64 fingerprint, with or without the SHA256: prefix.");
        return fp;
    }

    private static void ResolveHost(string host, out string hostName, out IReadOnlyList<string> v4, out IReadOnlyList<string> v6)
    {
        hostName = host; var ipv4 = new List<string>(); var ipv6 = new List<string>();
        try
        {
            IPHostEntry entry = Dns.GetHostEntry(host); if (!string.IsNullOrWhiteSpace(entry.HostName)) hostName = entry.HostName;
            foreach (IPAddress address in entry.AddressList)
            {
                if (address.AddressFamily == AddressFamily.InterNetwork) ipv4.Add(address.ToString());
                else if (address.AddressFamily == AddressFamily.InterNetworkV6) ipv6.Add(address.ToString());
            }
        }
        catch
        {
            if (IPAddress.TryParse(host, out IPAddress? address))
            {
                if (address.AddressFamily == AddressFamily.InterNetwork) ipv4.Add(address.ToString());
                else if (address.AddressFamily == AddressFamily.InterNetworkV6) ipv6.Add(address.ToString());
            }
        }
        v4 = ipv4.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(); v6 = ipv6.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static void AddError(List<string> errors, string message) { if (errors.Count < MaxRecordedErrors) errors.Add(message); }
    private static long SumSaturating(IEnumerable<long> values) { long total = 0; foreach (long value in values) total = SaturatingAdd(total, Math.Max(0, value)); return total; }
    private static long SaturatingAdd(long current, long value) => value > 0 && current > long.MaxValue - value ? long.MaxValue : current + value;

    private sealed record RemoteRootScan(
        RootCoverage Coverage, long ProjectFastPathFiles, long SignatureProbesAvoided, int JvmProjectsDetected,
        long GeneratedDirectoriesSkipped, long LinuxPolicyDirectoriesSkipped,
        IReadOnlyList<ProjectVolumeStat> ProjectVolumes, IReadOnlyList<BackupSet> ProjectSets,
        IReadOnlyList<BackupSet> ServiceSets, string? Error);
}

public sealed class SshKnownHostsStore
{
    private readonly string _path;
    private readonly Dictionary<string, string> _entries;
    private SshKnownHostsStore(string path, Dictionary<string, string> entries) { _path = path; _entries = entries; }

    public static string GetDefaultPath()
    {
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrWhiteSpace(home)) home = Environment.CurrentDirectory;
        return Path.Combine(home, ".smartbackupdiscovery", "ssh-known-hosts.json");
    }

    public static SshKnownHostsStore Load(string path)
    {
        string full = Path.GetFullPath(path);
        string parent = Path.GetDirectoryName(full) ?? Environment.CurrentDirectory;
        ManifestWriter.EnsureNoReparseAncestors(parent);
        if (!File.Exists(full)) return new SshKnownHostsStore(full, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));
        if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0) throw new IOException("Refusing to read a reparse-point SSH known-hosts file.");
        try
        {
            var data = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(full)) ?? new();
            return new SshKnownHostsStore(full, new Dictionary<string, string>(data, StringComparer.OrdinalIgnoreCase));
        }
        catch (Exception ex) { throw new InvalidDataException($"SSH known-hosts store is invalid: {full}", ex); }
    }

    public bool TryGet(string host, int port, out string? fingerprint)
    {
        if (_entries.TryGetValue(Key(host, port), out string? fp)) { fingerprint = RemoteLinuxSftpDiscovery.NormalizeFingerprint(fp); return true; }
        fingerprint = null; return false;
    }

    public void Set(string host, int port, string fingerprint) => _entries[Key(host, port)] = RemoteLinuxSftpDiscovery.NormalizeFingerprint(fingerprint)!;

    public void Save()
    {
        string parent = Path.GetDirectoryName(_path) ?? Environment.CurrentDirectory;
        ManifestWriter.EnsureNoReparseAncestors(parent); Directory.CreateDirectory(parent); ManifestWriter.EnsureNoReparseAncestors(parent);
        if (File.Exists(_path) && (File.GetAttributes(_path) & FileAttributes.ReparsePoint) != 0) throw new IOException("Refusing to overwrite a reparse-point SSH known-hosts file.");
        string temp = Path.Combine(parent, $".ssh-known-hosts-{Guid.NewGuid():N}.tmp");
        try
        {
            File.WriteAllText(temp, JsonSerializer.Serialize(_entries.OrderBy(x => x.Key).ToDictionary(x => x.Key, x => x.Value), new JsonSerializerOptions { WriteIndented = true }));
            File.Move(temp, _path, overwrite: true);
        }
        finally { try { if (File.Exists(temp)) File.Delete(temp); } catch { } }
    }

    private static string Key(string host, int port) => $"{host.ToLowerInvariant()}:{port}";
}

public static class LinuxServiceCatalog
{
    public sealed record ServiceDefinition(string Path, string Name, string BackupGuidance);
    public static IReadOnlyList<ServiceDefinition> Services { get; } = new[]
    {
        new ServiceDefinition("/var/lib/postgresql", "PostgreSQL", "Use a PostgreSQL-aware backup or a consistent storage snapshot; raw live files alone are not considered a valid logical backup."),
        new ServiceDefinition("/var/lib/mysql", "MySQL/MariaDB", "Use a MySQL/MariaDB-aware backup or a consistent storage snapshot; raw live files alone may be inconsistent."),
        new ServiceDefinition("/var/lib/mariadb", "MariaDB", "Use a MariaDB-aware backup or a consistent storage snapshot; raw live files alone may be inconsistent."),
        new ServiceDefinition("/var/lib/redis", "Redis", "Protect Redis persistence data and configuration with a consistent snapshot/backup policy."),
        new ServiceDefinition("/var/lib/libvirt/images", "libvirt/KVM virtual machines", "Protect VM disks with a hypervisor-aware or filesystem-consistent backup method."),
        new ServiceDefinition("/var/lib/docker/volumes", "Docker persistent volumes", "Protect persistent container volumes using workload-aware or filesystem-consistent backup methods."),
        new ServiceDefinition("/var/lib/containers/storage/volumes", "Container persistent volumes", "Protect persistent container volumes using workload-aware or filesystem-consistent backup methods.")
    };
}
