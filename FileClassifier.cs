namespace SmartBackupDiscovery;

public static class FileClassifier
{
    private static readonly HashSet<string> DatabaseExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".mdf", ".ndf", ".ldf", ".bak", ".trn", ".sqlite", ".sqlite3", ".db", ".db3", ".fdb", ".gdb", ".ib", ".ibd", ".frm", ".myd", ".myi", ".accdb", ".mdb", ".dbf"
    };
    private static readonly HashSet<string> DocumentExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf", ".doc", ".docx", ".docm", ".odt", ".rtf", ".txt", ".one", ".vsdx", ".xmind"
    };
    private static readonly HashSet<string> SpreadsheetExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".xls", ".xlsx", ".xlsm", ".ods", ".csv", ".tsv"
    };
    private static readonly HashSet<string> PresentationExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ppt", ".pptx", ".pptm", ".odp"
    };
    private static readonly HashSet<string> EmailExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pst", ".ost", ".olm", ".mbox", ".eml", ".msg"
    };
    private static readonly HashSet<string> ArchiveExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".zst"
    };
    private static readonly HashSet<string> VmExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".vhd", ".vhdx", ".avhdx", ".vmdk", ".qcow", ".qcow2", ".ova", ".ovf", ".vmx", ".vbox", ".nvram"
    };
    private static readonly HashSet<string> DatasetExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".parquet", ".feather", ".h5", ".hdf5", ".sav", ".dta", ".rdata", ".rds", ".mat", ".arrow"
    };
    private static readonly HashSet<string> CreativeExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".psd", ".psb", ".ai", ".indd", ".blend", ".dwg", ".dxf", ".step", ".stp", ".3ds", ".max", ".skp", ".kra", ".xcf", ".afdesign", ".afphoto"
    };
    private static readonly HashSet<string> GenericBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".msi", ".msp", ".sys", ".cab", ".appx", ".msix", ".so", ".dylib", ".class", ".jar", ".war"
    };
    private static readonly HashSet<string> ConfigExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".config", ".xml"
    };
    private static readonly HashSet<string> SourceCodeExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".java", ".kt", ".kts", ".scala", ".groovy", ".clj", ".cljs",
        ".cs", ".fs", ".fsx", ".vb", ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp",
        ".py", ".js", ".jsx", ".ts", ".tsx", ".rs", ".go", ".swift", ".php", ".rb", ".lua"
    };
    private static readonly HashSet<string> JvmSourceExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".java", ".kt", ".kts", ".scala", ".groovy", ".clj", ".cljs"
    };
    private static readonly string[] FinanceLegalTerms =
    {
        "invoice", "rechnung", "steuer", "tax", "vertrag", "contract", "insurance", "versicherung", "court", "gericht", "bescheid", "certificate", "zeugnis", "diplom", "diploma", "فاکتور", "مالیات", "قرارداد", "بیمه", "دادگاه", "گواهی"
    };

    public static FileCandidate Analyze(
        string path,
        string sourceId,
        bool inspectOfficeProtection,
        ContentInspectionProfile profile,
        ResourceGovernor? governor = null,
        string? remoteHost = null,
        FileAttributes? knownAttributes = null)
    {
        var file = new FileInfo(path);
        long size = 0;
        DateTime lastWrite = DateTime.MinValue;
        try { size = file.Length; lastWrite = file.LastWriteTimeUtc; } catch { }

        string ext = file.Extension;
        string name = file.Name;
        var evidence = new List<DetectionEvidence>();
        FileCategory category = FileCategory.Other;
        bool mustInclude = false;

        if (GenericBinaries.Contains(ext))
        {
            return new FileCandidate(path, size, lastWrite, 0, BackupPriority.Ignore, FileCategory.Other, false,
                sourceId, Array.Empty<DetectionEvidence>(), InspectionStatus.NotRequested, 0,
                ReasonCode: "GENERIC_BINARY_IGNORED");
        }

        AddByExtension(ext, evidence, ref category, ref mustInclude);
        AddFilenameContext(name, evidence, ref category);
        if (LinuxBackupHints.GetHint(path) is { } linuxHint)
        {
            category = Prefer(category, linuxHint.Category);
            evidence.Add(new DetectionEvidence(linuxHint.RuleId, linuxHint.Summary, "linux-config", linuxHint.Score, EvidenceConfidence.High, linuxHint.MustInclude));
            if (linuxHint.MustInclude) mustInclude = true;
        }
        bool projectMarker = IsProjectMarkerName(name);
        if (projectMarker)
        {
            category = FileCategory.Project;
            evidence.Add(new DetectionEvidence("PROJECT_MARKER", "Project marker file", "project", 140, EvidenceConfidence.High));
        }

        SignatureResult signature = new(null, Array.Empty<DetectionEvidence>(), 0);
        // Avoid opening every obvious user file merely to re-confirm its extension. Signature
        // probing remains for unknown files (renamed SQLite/PDF/OLE/ZIP) and database candidates.
        if (!LinuxBackupHints.ShouldAvoidSignatureProbe(path) &&
            (category is FileCategory.Other or FileCategory.Database) && !projectMarker && !IsSourceCodeFileName(name))
        {
            signature = FileSignatureDetector.Analyze(path, governor, remoteHost);
            evidence.AddRange(signature.Evidence);
            if (signature.SuggestedCategory is { } sigCategory)
                category = Prefer(category, sigCategory);
            if (signature.Evidence.Any(x => x.MustInclude))
                mustInclude = true;
        }

        InspectionStatus inspectionStatus = InspectionStatus.NotRequested;
        long inspectedBytes = signature.InspectedBytes;
        string? reasonCode = null;
        string? warning = null;
        bool protectionDetected = false;
        string? protectionType = null;

        if (inspectOfficeProtection)
        {
            var office = BackupContentDetector.Analyze(path, profile, governor, remoteHost);
            if (office.Status != InspectionStatus.Unsupported)
            {
                inspectionStatus = office.Status;
                inspectedBytes += office.InspectedBytes;
                evidence.AddRange(office.Evidence);
                if (office.SuggestedCategory is { } officeCategory)
                    category = Prefer(category, officeCategory);
                reasonCode = office.ReasonCode;
                warning = office.Warning;
                protectionDetected = office.ProtectionDetected;
                protectionType = office.ProtectionType;
            }
        }

        int score = ComputeScore(evidence, mustInclude);
        if (score <= 0 && category == FileCategory.Other)
        {
            return new FileCandidate(path, size, lastWrite, 0, BackupPriority.Ignore, category, false,
                sourceId, evidence, inspectionStatus, inspectedBytes, reasonCode, warning, protectionDetected, protectionType);
        }

        if (protectionDetected)
            score = Math.Max(score, 165);

        BackupPriority priority = score switch
        {
            >= 180 => BackupPriority.Critical,
            >= 120 => BackupPriority.High,
            >= 70 => BackupPriority.Normal,
            > 0 => BackupPriority.Low,
            _ => BackupPriority.Ignore
        };

        return new FileCandidate(path, size, lastWrite, score, priority, category, mustInclude,
            sourceId, evidence, inspectionStatus, inspectedBytes, reasonCode, warning, protectionDetected, protectionType);
    }

    public static FileCandidate AnalyzeRemoteLinuxMetadata(
        string displayPath,
        string remoteLinuxPath,
        string fileName,
        long size,
        DateTime lastWriteTimeUtc,
        string sourceId)
    {
        string ext = Path.GetExtension(fileName);
        var evidence = new List<DetectionEvidence>();
        FileCategory category = FileCategory.Other;
        bool mustInclude = false;

        if (GenericBinaries.Contains(ext))
        {
            return new FileCandidate(displayPath, Math.Max(0, size), lastWriteTimeUtc, 0, BackupPriority.Ignore, FileCategory.Other, false,
                sourceId, Array.Empty<DetectionEvidence>(), InspectionStatus.NotRequested, 0,
                ReasonCode: "GENERIC_BINARY_IGNORED");
        }

        AddByExtension(ext, evidence, ref category, ref mustInclude);
        AddFilenameContext(fileName, evidence, ref category);
        if (LinuxBackupHints.GetHintForRemotePath(remoteLinuxPath) is { } linuxHint)
        {
            category = Prefer(category, linuxHint.Category);
            evidence.Add(new DetectionEvidence(linuxHint.RuleId, linuxHint.Summary, "linux-config", linuxHint.Score, EvidenceConfidence.High, linuxHint.MustInclude));
            if (linuxHint.MustInclude) mustInclude = true;
        }

        bool projectMarker = IsProjectMarkerName(fileName);
        if (projectMarker)
        {
            category = FileCategory.Project;
            evidence.Add(new DetectionEvidence("PROJECT_MARKER", "Project marker file", "project", 140, EvidenceConfidence.High));
        }

        int score = ComputeScore(evidence, mustInclude);
        if (score <= 0 && category == FileCategory.Other)
        {
            return new FileCandidate(displayPath, Math.Max(0, size), lastWriteTimeUtc, 0, BackupPriority.Ignore, category, false,
                sourceId, evidence, InspectionStatus.NotRequested, 0, "REMOTE_METADATA_ONLY");
        }

        BackupPriority priority = score switch
        {
            >= 180 => BackupPriority.Critical,
            >= 120 => BackupPriority.High,
            >= 70 => BackupPriority.Normal,
            > 0 => BackupPriority.Low,
            _ => BackupPriority.Ignore
        };

        return new FileCandidate(displayPath, Math.Max(0, size), lastWriteTimeUtc, score, priority, category, mustInclude,
            sourceId, evidence, InspectionStatus.NotRequested, 0,
            ReasonCode: "REMOTE_METADATA_ONLY",
            Warning: "Remote Linux SFTP discovery classified this item from path/name/metadata only; file content was not downloaded or inspected.");
    }

    public static bool ShouldSkipProjectDirectory(string path)
    {
        string name = Path.GetFileName(path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        return ShouldSkipProjectDirectoryName(name);
    }

    public static bool ShouldSkipProjectDirectoryName(string name)
    {
        return name.Equals("bin", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("obj", StringComparison.OrdinalIgnoreCase) ||
               name.Equals(".vs", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("node_modules", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("dist", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("build", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("target", StringComparison.OrdinalIgnoreCase) ||
               name.Equals(".gradle", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("out", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("classes", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("generated", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("generated-sources", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("generated-test-sources", StringComparison.OrdinalIgnoreCase) ||
               name.Equals(".next", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("coverage", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("__pycache__", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsProjectMarkerName(string name)
    {
        string lower = name.ToLowerInvariant();
        return lower == ".git" || lower.EndsWith(".sln") || lower.EndsWith(".csproj") ||
               lower == "pyproject.toml" || lower == "requirements.txt" || lower == "package.json" ||
               lower == "pom.xml" || lower == "build.gradle" || lower == "build.gradle.kts" ||
               lower == "settings.gradle" || lower == "settings.gradle.kts" || lower == "gradle.properties" ||
               lower == "gradlew" || lower == "gradlew.bat" || lower == "mvnw" || lower == "mvnw.cmd" ||
               lower == "build.xml" || lower == "ivy.xml" || lower == "androidmanifest.xml" ||
               lower == ".project" || lower == ".classpath" ||
               lower == "docker-compose.yml" || lower == "docker-compose.yaml" || lower == "compose.yml" || lower == "compose.yaml" ||
               lower == "makefile" || lower == "cmakelists.txt" ||
               lower == "cargo.toml" || lower == "go.mod" || lower.EndsWith(".xcodeproj");
    }

    public static bool IsSourceCodeFileName(string name) => SourceCodeExtensions.Contains(Path.GetExtension(name));

    public static bool IsJvmSourceFileName(string name) => JvmSourceExtensions.Contains(Path.GetExtension(name));

    public static bool WouldProbeSignature(string name)
    {
        string ext = Path.GetExtension(name);
        if (GenericBinaries.Contains(ext) || SourceCodeExtensions.Contains(ext) || IsProjectMarkerName(name))
            return false;
        return !DocumentExtensions.Contains(ext) && !SpreadsheetExtensions.Contains(ext) &&
               !PresentationExtensions.Contains(ext) && !EmailExtensions.Contains(ext) &&
               !ArchiveExtensions.Contains(ext) && !VmExtensions.Contains(ext) &&
               !DatasetExtensions.Contains(ext) && !CreativeExtensions.Contains(ext) &&
               !ConfigExtensions.Contains(ext);
    }

    private static void AddByExtension(string ext, List<DetectionEvidence> evidence, ref FileCategory category, ref bool mustInclude)
    {
        if (DatabaseExtensions.Contains(ext))
        {
            category = FileCategory.Database;
            mustInclude = true;
            evidence.Add(new DetectionEvidence("EXT_DATABASE", "Database data/backup file extension", "type", 190, EvidenceConfidence.High, true));
        }
        else if (EmailExtensions.Contains(ext))
        {
            category = FileCategory.Email;
            evidence.Add(new DetectionEvidence("EXT_MAIL", "Mail/message archive extension", "type", 150, EvidenceConfidence.High));
        }
        else if (VmExtensions.Contains(ext))
        {
            category = FileCategory.VirtualMachine;
            evidence.Add(new DetectionEvidence("EXT_VM", "Virtual-machine disk/configuration extension", "type", 155, EvidenceConfidence.High));
        }
        else if (CreativeExtensions.Contains(ext))
        {
            category = FileCategory.Creative;
            evidence.Add(new DetectionEvidence("EXT_CREATIVE", "Creative/CAD source-file extension", "type", 120, EvidenceConfidence.High));
        }
        else if (DatasetExtensions.Contains(ext))
        {
            category = FileCategory.Dataset;
            evidence.Add(new DetectionEvidence("EXT_DATASET", "Analytical/scientific dataset extension", "type", 115, EvidenceConfidence.High));
        }
        else if (SpreadsheetExtensions.Contains(ext))
        {
            category = FileCategory.Spreadsheet;
            evidence.Add(new DetectionEvidence("EXT_SPREADSHEET", "Spreadsheet/data-table document extension", "type", 100, EvidenceConfidence.High));
        }
        else if (PresentationExtensions.Contains(ext))
        {
            category = FileCategory.Presentation;
            evidence.Add(new DetectionEvidence("EXT_PRESENTATION", "Presentation document extension", "type", 95, EvidenceConfidence.High));
        }
        else if (DocumentExtensions.Contains(ext))
        {
            category = FileCategory.Document;
            evidence.Add(new DetectionEvidence("EXT_DOCUMENT", "User document extension", "type", 95, EvidenceConfidence.High));
        }
        else if (ArchiveExtensions.Contains(ext))
        {
            category = FileCategory.Archive;
            evidence.Add(new DetectionEvidence("EXT_ARCHIVE", "Archive/export container extension", "type", 80, EvidenceConfidence.Medium));
        }
        else if (ConfigExtensions.Contains(ext))
        {
            category = FileCategory.Configuration;
            evidence.Add(new DetectionEvidence("EXT_CONFIGURATION", "Configuration/structured-text extension", "type", 45, EvidenceConfidence.Medium));
        }
    }

    private static void AddFilenameContext(string name, List<DetectionEvidence> evidence, ref FileCategory category)
    {
        foreach (string term in FinanceLegalTerms)
        {
            if (!name.Contains(term, StringComparison.OrdinalIgnoreCase))
                continue;
            category = FileCategory.FinanceLegal;
            evidence.Add(new DetectionEvidence("NAME_FINANCE_LEGAL", "Filename suggests finance/legal/administrative importance", "context", 125, EvidenceConfidence.Medium));
            break;
        }
    }

    private static int ComputeScore(IReadOnlyList<DetectionEvidence> evidence, bool mustInclude)
    {
        if (evidence.Count == 0)
            return 0;
        int grouped = evidence
            .GroupBy(x => x.SignalGroup, StringComparer.OrdinalIgnoreCase)
            .Sum(group => group.Max(x => x.Score));
        if (mustInclude)
            grouped = Math.Max(grouped, 180);
        return Math.Min(250, grouped);
    }

    private static FileCategory Prefer(FileCategory current, FileCategory incoming)
    {
        if (current == FileCategory.Other) return incoming;
        if (incoming == FileCategory.Database) return incoming;
        if (current == FileCategory.Configuration && incoming != FileCategory.Configuration) return incoming;
        return current;
    }
}
