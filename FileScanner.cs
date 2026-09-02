namespace SmartBackupDiscovery;

public sealed record ProjectVolumeStat(string Root, long Files, long Bytes, bool JvmDetected);

public sealed record ScanPerformanceSummary(
    long ProjectFastPathFiles,
    long SignatureProbesAvoided,
    int JvmProjectsDetected,
    long GeneratedDirectoriesSkipped,
    long LinuxPolicyDirectoriesSkipped = 0,
    long MountBoundariesSkipped = 0)
{
    public static ScanPerformanceSummary Empty { get; } = new(0, 0, 0, 0, 0, 0);
}

public sealed record ScanResult(
    IReadOnlyList<FileCandidate> Candidates,
    IReadOnlyList<string> Errors,
    ScanCoverage Coverage,
    IReadOnlyList<string> ProjectRoots,
    IReadOnlyList<ProjectVolumeStat> ProjectVolumes,
    ScanPerformanceSummary Performance);

public sealed class FileScanner
{
    private const int MaxRecordedErrors = 5000;
    private const int ProgressIntervalMilliseconds = 1500;

    public ScanResult Scan(
        IReadOnlyList<string> roots,
        IReadOnlyList<SourceDescriptor> sources,
        bool inspectOfficeProtection,
        ContentInspectionProfile profile,
        ResourceGovernor governor,
        TraversalLimits limits,
        Action<ScanProgress>? progress = null,
        Action<FileCandidate>? onCandidate = null,
        PlatformTraversalOptions? platformOptions = null)
    {
        var allCandidates = new Dictionary<string, FileCandidate>(PathRules.Comparer);
        var errors = new List<string>();
        var projectRoots = new HashSet<string>(PathRules.Comparer);
        var jvmProjectRoots = new HashSet<string>(PathRules.Comparer);
        var projectVolumeFiles = new Dictionary<string, long>(PathRules.Comparer);
        var projectVolumeBytes = new Dictionary<string, long>(PathRules.Comparer);
        var platformPolicy = new PlatformScanPolicy(roots, platformOptions ?? PlatformTraversalOptions.Default);
        var coverageRoots = new List<RootCoverage>();
        long totalDirs = 0, totalFiles = 0, totalCandidates = 0, totalPolicySkipped = 0, totalReparseDirs = 0, totalReparseFiles = 0;
        long projectFastPathFiles = 0, signatureProbesAvoided = 0;
        long generatedDirectoriesSkipped = 0, linuxPolicyDirectoriesSkipped = 0, mountBoundariesSkipped = 0;
        long lastProgressTicks = Environment.TickCount64;

        foreach (string rootValue in roots)
        {
            string root;
            try { root = Path.GetFullPath(rootValue); }
            catch (Exception ex)
            {
                AddError(errors, $"Invalid root '{rootValue}': {ex.Message}");
                coverageRoots.Add(new RootCoverage(rootValue, false, false, 0, 0, 0, 0, 0, 0, 1));
                continue;
            }

            bool exists = Directory.Exists(root);
            if (!exists)
            {
                AddError(errors, $"Root is unavailable: {root}");
                coverageRoots.Add(new RootCoverage(root, false, false, 0, 0, 0, 0, 0, 0, 1));
                continue;
            }
            if (platformPolicy.ShouldSkipDirectory(root, root, out PlatformSkipReason rootSkipReason))
            {
                AddError(errors, $"Root is excluded by Linux traversal policy ({rootSkipReason}): {root}. Use --include-system-mounts only when this is intentional.");
                coverageRoots.Add(new RootCoverage(root, true, false, 0, 0, 0, 1, 0, 0, 1));
                totalPolicySkipped++; linuxPolicyDirectoriesSkipped++;
                continue;
            }

            long rootDirs = 0, rootFiles = 0, rootCandidates = 0, rootPolicy = 0, rootReparseDirs = 0, rootReparseFiles = 0, rootErrors = 0;
            bool completed = true;
            var stack = new Stack<(string Path, int Depth, string? ProjectRoot)>();
            stack.Push((root, 0, null));
            var visited = new HashSet<string>(PathRules.Comparer);

            while (stack.Count > 0)
            {
                if (totalDirs >= limits.MaxDirectories || totalFiles >= limits.MaxFiles)
                {
                    completed = false;
                    AddError(errors, "Traversal budget reached; remaining paths were not scanned.");
                    break;
                }

                var (dir, depth, inheritedProjectRoot) = stack.Pop();
                if (!visited.Add(dir))
                    continue;
                if (depth > limits.MaxDepth)
                {
                    completed = false;
                    rootErrors++;
                    AddError(errors, $"Maximum depth {limits.MaxDepth} exceeded under: {dir}");
                    continue;
                }

                governor.BeforeWork(IsUnc(dir));
                List<FileSystemInfo> entries;
                try
                {
                    var di = new DirectoryInfo(dir);
                    if ((di.Attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        rootReparseDirs++; totalReparseDirs++;
                        continue;
                    }
                    entries = di.EnumerateFileSystemInfos().ToList();
                }
                catch (Exception ex)
                {
                    completed = false;
                    rootErrors++;
                    AddError(errors, $"Cannot enumerate {dir}: {ex.Message}");
                    continue;
                }

                rootDirs++; totalDirs++;
                string? currentProjectRoot = inheritedProjectRoot;
                if (currentProjectRoot is null)
                {
                    if (DirectoryHasProjectMarker(entries))
                    {
                        currentProjectRoot = dir;
                        projectRoots.Add(dir);
                    }
                    else if (TryDetectJvmProjectRoot(dir, entries, root, depth, out string? detectedJvmRoot))
                    {
                        currentProjectRoot = detectedJvmRoot;
                        projectRoots.Add(detectedJvmRoot!);
                        jvmProjectRoots.Add(detectedJvmRoot!);
                    }
                }

                foreach (var entry in entries)
                {
                    FileAttributes attrs;
                    try { attrs = entry.Attributes; }
                    catch (Exception ex)
                    {
                        rootErrors++;
                        AddError(errors, $"Cannot inspect {entry.FullName}: {ex.Message}");
                        continue;
                    }

                    if ((attrs & FileAttributes.Directory) != 0)
                        continue;
                    if ((attrs & FileAttributes.ReparsePoint) != 0)
                    {
                        rootReparseFiles++; totalReparseFiles++;
                        continue;
                    }

                    rootFiles++; totalFiles++;
                    if (totalFiles > limits.MaxFiles)
                    {
                        completed = false;
                        break;
                    }

                    if (currentProjectRoot is not null)
                        AddProjectVolume(currentProjectRoot, entry);

                    bool isMarker = FileClassifier.IsProjectMarkerName(entry.Name);
                    bool fastProjectMember = currentProjectRoot is not null && !isMarker && !IsAlwaysClassifyInProject(entry.Name);
                    if (fastProjectMember)
                    {
                        projectFastPathFiles++;
                        if (FileClassifier.IsSourceCodeFileName(entry.Name) || FileClassifier.WouldProbeSignature(entry.Name))
                            signatureProbesAvoided++;
                        MaybeProgress(dir);
                        continue;
                    }

                    // Loose source code outside a detected project should never incur a signature read.
                    // It is metadata-only unless the surrounding directory is recognized as a source tree.
                    if (currentProjectRoot is null && FileClassifier.IsSourceCodeFileName(entry.Name))
                    {
                        signatureProbesAvoided++;
                        MaybeProgress(dir);
                        continue;
                    }

                    if (LinuxBackupHints.ShouldAvoidSignatureProbe(entry.FullName) && FileClassifier.WouldProbeSignature(entry.Name))
                        signatureProbesAvoided++;

                    var source = SourceIdentityProvider.FindSourceForPath(sources, entry.FullName);
                    string sourceId = source?.Id ?? "unknown";
                    string? remoteHost = source?.Kind == SourceKind.Smb ? source.HostReference : null;
                    try
                    {
                        var candidate = FileClassifier.Analyze(
                            entry.FullName,
                            sourceId,
                            inspectOfficeProtection,
                            profile,
                            governor,
                            remoteHost,
                            attrs);

                        if (isMarker)
                        {
                            var markerEvidence = candidate.Evidence.Any(x => x.RuleId == "PROJECT_MARKER")
                                ? candidate.Evidence
                                : candidate.Evidence.Concat(new[]
                                {
                                    new DetectionEvidence("PROJECT_MARKER", "Project marker file", "project", 140, EvidenceConfidence.High)
                                }).ToArray();
                            candidate = candidate with
                            {
                                Score = Math.Max(140, candidate.Score),
                                Priority = BackupPriority.High,
                                Category = FileCategory.Project,
                                Evidence = markerEvidence,
                                ReasonCode = candidate.ReasonCode ?? "PROJECT_MARKER"
                            };
                        }

                        if (candidate.Score > 0 || candidate.MustInclude || candidate.ProtectionDetected)
                        {
                            allCandidates[entry.FullName] = candidate;
                            rootCandidates++; totalCandidates++;
                            onCandidate?.Invoke(candidate);
                        }
                    }
                    catch (Exception ex)
                    {
                        rootErrors++;
                        AddError(errors, $"Classification failed for {entry.FullName}: {ex.Message}");
                    }

                    MaybeProgress(dir);
                }

                foreach (var entry in entries)
                {
                    FileAttributes attrs;
                    try { attrs = entry.Attributes; } catch { continue; }
                    if ((attrs & FileAttributes.Directory) == 0)
                        continue;
                    if ((attrs & FileAttributes.ReparsePoint) != 0)
                        continue;
                    if (currentProjectRoot is not null && FileClassifier.ShouldSkipProjectDirectory(entry.FullName))
                    {
                        rootPolicy++; totalPolicySkipped++; generatedDirectoriesSkipped++;
                        continue;
                    }
                    if (platformPolicy.ShouldSkipDirectory(entry.FullName, root, out PlatformSkipReason platformReason))
                    {
                        rootPolicy++; totalPolicySkipped++; linuxPolicyDirectoriesSkipped++;
                        if (platformReason == PlatformSkipReason.MountBoundary) mountBoundariesSkipped++;
                        continue;
                    }
                    if (depth + 1 <= limits.MaxDepth)
                        stack.Push((entry.FullName, depth + 1, currentProjectRoot));
                }
            }

            coverageRoots.Add(new RootCoverage(root, true, completed, rootDirs, rootFiles, rootCandidates, rootPolicy, rootReparseDirs, rootReparseFiles, rootErrors));
        }

        var ordered = allCandidates.Values
            .OrderByDescending(x => x.Score)
            .ThenBy(x => x.Path, PathRules.Comparer)
            .ToArray();

        var volumes = projectRoots
            .OrderBy(x => x, PathRules.Comparer)
            .Select(projectRoot => new ProjectVolumeStat(
                projectRoot,
                projectVolumeFiles.GetValueOrDefault(projectRoot),
                projectVolumeBytes.GetValueOrDefault(projectRoot),
                jvmProjectRoots.Contains(projectRoot)))
            .ToArray();

        return new ScanResult(
            ordered,
            errors,
            new ScanCoverage(coverageRoots, totalDirs, totalFiles, ordered.LongLength, totalPolicySkipped, totalReparseDirs, totalReparseFiles),
            projectRoots.OrderBy(x => x, PathRules.Comparer).ToArray(),
            volumes,
            new ScanPerformanceSummary(projectFastPathFiles, signatureProbesAvoided, jvmProjectRoots.Count, generatedDirectoriesSkipped, linuxPolicyDirectoriesSkipped, mountBoundariesSkipped));

        void MaybeProgress(string currentDirectory)
        {
            long now = Environment.TickCount64;
            if (progress is null || now - lastProgressTicks < ProgressIntervalMilliseconds)
                return;
            lastProgressTicks = now;
            progress(new ScanProgress(totalFiles, totalDirs, totalCandidates, currentDirectory, governor.AdaptiveDelayMilliseconds));
        }

        void AddProjectVolume(string projectRoot, FileSystemInfo entry)
        {
            long size = 0;
            try
            {
                if (entry is FileInfo file)
                    size = file.Length;
                else
                    size = new FileInfo(entry.FullName).Length;
            }
            catch { }
            projectVolumeFiles[projectRoot] = projectVolumeFiles.GetValueOrDefault(projectRoot) + 1;
            projectVolumeBytes[projectRoot] = SaturatingAdd(projectVolumeBytes.GetValueOrDefault(projectRoot), Math.Max(0, size));
        }
    }

    private static bool DirectoryHasProjectMarker(IEnumerable<FileSystemInfo> entries) =>
        entries.Any(entry => FileClassifier.IsProjectMarkerName(entry.Name));

    private static bool TryDetectJvmProjectRoot(
        string dir,
        IReadOnlyList<FileSystemInfo> entries,
        string scanRoot,
        int depth,
        out string? projectRoot)
    {
        projectRoot = null;

        if (TryInferJvmRootFromPath(dir, out string? inferred))
        {
            projectRoot = SourceIdentityProvider.IsSameOrUnder(inferred!, scanRoot) ? inferred : scanRoot;
            return true;
        }

        // Only issue nested existence probes when this directory actually has a "src" child.
        // That keeps the optimization cheap on large non-source trees and SMB shares.
        bool hasSrc = entries.Any(x => IsDirectory(x) && x.Name.Equals("src", StringComparison.OrdinalIgnoreCase));
        if (hasSrc && HasStandardJvmLayout(dir))
        {
            projectRoot = dir;
            return true;
        }

        // If the user starts directly at ...\src or ...\src\main, recognize the source container
        // without requiring traversal back to a build-file-bearing project root.
        if (TryDetectJvmSourceContainer(dir, entries, scanRoot, out string? containerRoot))
        {
            projectRoot = containerRoot;
            return true;
        }

        // Fallback for old source archives without Maven/Gradle metadata. This is restricted to
        // the user-selected root and uses a bounded metadata-only look-ahead so a broad drive/root
        // cannot accidentally become a project merely because it contains source somewhere below.
        if (depth == 0 && LooksLikeLooseJvmSourceRoot(dir, entries))
        {
            projectRoot = dir;
            return true;
        }

        return false;
    }


    private static bool LooksLikeLooseJvmSourceRoot(string dir, IReadOnlyList<FileSystemInfo> entries)
    {
        var directFiles = entries.Where(x => !IsDirectory(x)).ToArray();
        int directJvm = directFiles.Count(x => FileClassifier.IsJvmSourceFileName(x.Name));
        if (directJvm >= 5 && directJvm * 100 >= Math.Max(1, directFiles.Length) * 60)
            return true;

        string trimmed = dir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        string root = (Path.GetPathRoot(dir) ?? string.Empty).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (trimmed.Equals(root, PathRules.Comparison))
            return false;

        string name = Path.GetFileName(trimmed);
        bool sourceLikeName = new[] { "src", "source", "sources", "java", "code", "repo", "repos", "repository", "workspace", "project", "projects" }
            .Any(term => name.Contains(term, StringComparison.OrdinalIgnoreCase));
        bool hasPackageRoot = entries.Any(x => IsDirectory(x) &&
            (x.Name.Equals("com", StringComparison.OrdinalIgnoreCase) ||
             x.Name.Equals("org", StringComparison.OrdinalIgnoreCase) ||
             x.Name.Equals("net", StringComparison.OrdinalIgnoreCase) ||
             x.Name.Equals("io", StringComparison.OrdinalIgnoreCase) ||
             x.Name.Equals("edu", StringComparison.OrdinalIgnoreCase)));
        if (!sourceLikeName && !hasPackageRoot)
            return false;

        const int maxDirectories = 64;
        const int maxFiles = 200;
        const int maxDepth = 5;
        int directories = 0, files = 0, jvm = 0;
        var queue = new Queue<(string Path, int Depth)>();
        foreach (var child in entries.Where(IsDirectory))
            queue.Enqueue((child.FullName, 1));

        while (queue.Count > 0 && directories < maxDirectories && files < maxFiles)
        {
            var (path, depth) = queue.Dequeue();
            if (depth > maxDepth) continue;
            directories++;
            IEnumerable<FileSystemInfo> children;
            try
            {
                var di = new DirectoryInfo(path);
                if ((di.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                children = di.EnumerateFileSystemInfos();
            }
            catch { continue; }

            try
            {
                foreach (FileSystemInfo child in children)
                {
                    if (files >= maxFiles) break;
                    if (IsDirectory(child))
                    {
                        if (depth < maxDepth && !FileClassifier.ShouldSkipProjectDirectory(child.FullName))
                            queue.Enqueue((child.FullName, depth + 1));
                        continue;
                    }
                    files++;
                    if (FileClassifier.IsJvmSourceFileName(child.Name)) jvm++;
                    if (jvm >= 8 && jvm * 100 >= Math.Max(1, files) * 60) return true;
                }
            }
            catch { }
        }

        return jvm >= 5 && jvm * 100 >= Math.Max(1, files) * 60;
    }

    private static bool TryDetectJvmSourceContainer(
        string dir,
        IReadOnlyList<FileSystemInfo> entries,
        string scanRoot,
        out string? projectRoot)
    {
        projectRoot = null;
        string name = Path.GetFileName(dir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));

        if (name.Equals("src", StringComparison.OrdinalIgnoreCase))
        {
            bool hasLayout = new[]
            {
                Path.Combine("main", "java"), Path.Combine("test", "java"),
                Path.Combine("main", "kotlin"), Path.Combine("test", "kotlin"),
                Path.Combine("main", "scala"), Path.Combine("test", "scala"),
                Path.Combine("main", "groovy"), Path.Combine("test", "groovy")
            }.Any(relative => Directory.Exists(Path.Combine(dir, relative)));
            if (hasLayout)
            {
                string inferred = Path.GetDirectoryName(dir) ?? dir;
                projectRoot = SourceIdentityProvider.IsSameOrUnder(inferred, scanRoot) ? inferred : scanRoot;
                return true;
            }
        }

        bool isMainOrTest = name.Equals("main", StringComparison.OrdinalIgnoreCase) || name.Equals("test", StringComparison.OrdinalIgnoreCase);
        if (isMainOrTest)
        {
            DirectoryInfo? current = new DirectoryInfo(dir);
            DirectoryInfo? src = current.Parent;
            if (src is not null && src.Name.Equals("src", StringComparison.OrdinalIgnoreCase))
            {
                bool hasLanguageDir = entries.Any(x => IsDirectory(x) &&
                    (x.Name.Equals("java", StringComparison.OrdinalIgnoreCase) ||
                     x.Name.Equals("kotlin", StringComparison.OrdinalIgnoreCase) ||
                     x.Name.Equals("scala", StringComparison.OrdinalIgnoreCase) ||
                     x.Name.Equals("groovy", StringComparison.OrdinalIgnoreCase)));
                if (hasLanguageDir)
                {
                    string inferred = src.Parent?.FullName ?? src.FullName;
                    projectRoot = SourceIdentityProvider.IsSameOrUnder(inferred, scanRoot) ? inferred : scanRoot;
                    return true;
                }
            }
        }

        return false;
    }

    private static bool TryInferJvmRootFromPath(string dir, out string? projectRoot)
    {
        projectRoot = null;
        try
        {
            DirectoryInfo? cursor = new DirectoryInfo(Path.GetFullPath(dir));
            while (cursor is not null)
            {
                bool language = cursor.Name.Equals("java", StringComparison.OrdinalIgnoreCase) ||
                                cursor.Name.Equals("kotlin", StringComparison.OrdinalIgnoreCase) ||
                                cursor.Name.Equals("scala", StringComparison.OrdinalIgnoreCase) ||
                                cursor.Name.Equals("groovy", StringComparison.OrdinalIgnoreCase);
                DirectoryInfo? mainOrTest = cursor.Parent;
                DirectoryInfo? src = mainOrTest?.Parent;
                if (language && mainOrTest is not null && src is not null &&
                    (mainOrTest.Name.Equals("main", StringComparison.OrdinalIgnoreCase) || mainOrTest.Name.Equals("test", StringComparison.OrdinalIgnoreCase)) &&
                    src.Name.Equals("src", StringComparison.OrdinalIgnoreCase))
                {
                    projectRoot = src.Parent?.FullName ?? src.FullName;
                    return true;
                }
                cursor = cursor.Parent;
            }
        }
        catch { }
        return false;
    }

    private static bool HasStandardJvmLayout(string dir)
    {
        string[] relative =
        {
            Path.Combine("src", "main", "java"), Path.Combine("src", "test", "java"),
            Path.Combine("src", "main", "kotlin"), Path.Combine("src", "test", "kotlin"),
            Path.Combine("src", "main", "scala"), Path.Combine("src", "test", "scala"),
            Path.Combine("src", "main", "groovy"), Path.Combine("src", "test", "groovy")
        };
        return relative.Any(path => Directory.Exists(Path.Combine(dir, path)));
    }

    private static bool IsDirectory(FileSystemInfo info)
    {
        try { return (info.Attributes & FileAttributes.Directory) != 0; }
        catch { return false; }
    }

    private static bool IsAlwaysClassifyInProject(string name)
    {
        string ext = Path.GetExtension(name);
        return ext.Equals(".mdf", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".ldf", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".bak", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".sqlite", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".db", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".docx", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".xlsx", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".xls", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".doc", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".pdf", StringComparison.OrdinalIgnoreCase);
    }

    private static long SaturatingAdd(long current, long value) =>
        value > 0 && current > long.MaxValue - value ? long.MaxValue : current + value;

    private static bool IsUnc(string path) => path.StartsWith(@"\\", StringComparison.Ordinal);

    private static void AddError(List<string> errors, string error)
    {
        if (errors.Count < MaxRecordedErrors)
            errors.Add(error);
    }
}
