namespace SmartBackupDiscovery;

public enum FileCategory
{
    Other,
    Database,
    Project,
    Document,
    Spreadsheet,
    Presentation,
    Email,
    Archive,
    VirtualMachine,
    Dataset,
    Creative,
    FinanceLegal,
    Configuration
}

public enum BackupPriority
{
    Ignore = 0,
    Low = 1,
    Normal = 2,
    High = 3,
    Critical = 4
}

public enum InspectionStatus
{
    NotRequested,
    Full,
    Partial,
    Unsupported,
    EncryptedOrProtected,
    AccessDenied,
    Failed
}

public enum EvidenceConfidence
{
    Low,
    Medium,
    High
}

public enum ContentInspectionProfile
{
    Balanced,
    Deep
}

public enum SourceKind
{
    Local,
    Smb,
    LinuxLocal,
    LinuxSftp
}

public enum RemoteAuthenticationStatus
{
    NotAttempted,
    Succeeded,
    Partial,
    Failed,
    UnsupportedPlatform
}

public sealed record DetectionEvidence(
    string RuleId,
    string Summary,
    string SignalGroup,
    int Score,
    EvidenceConfidence Confidence,
    bool MustInclude = false);

public sealed record FileCandidate(
    string Path,
    long Size,
    DateTime LastWriteTimeUtc,
    int Score,
    BackupPriority Priority,
    FileCategory Category,
    bool MustInclude,
    string SourceId,
    IReadOnlyList<DetectionEvidence> Evidence,
    InspectionStatus InspectionStatus,
    long InspectedBytes,
    string? ReasonCode = null,
    string? Warning = null,
    bool ProtectionDetected = false,
    string? ProtectionType = null);

public sealed record BackupSet(
    string Id,
    string Type,
    string Name,
    int Score,
    BackupPriority Priority,
    IReadOnlyList<string> SourcePaths,
    IReadOnlyList<string> Reasons,
    IReadOnlyList<string> SourceIds);

public sealed record HostIdentity(
    string Role,
    string HostReference,
    string HostName,
    IReadOnlyList<string> IPv4Addresses,
    IReadOnlyList<string> IPv6Addresses);

public sealed record SourceDescriptor(
    string Id,
    SourceKind Kind,
    string Root,
    string HostReference,
    string? Share,
    string? Volume);

public sealed record RemoteShareAccessReport(
    string Share,
    string Root,
    bool Connected,
    int? ErrorCode,
    string? Error);

public sealed record RemoteTargetReport(
    string HostReference,
    string HostName,
    IReadOnlyList<string> IPv4Addresses,
    IReadOnlyList<string> IPv6Addresses,
    string AuthenticationMode,
    RemoteAuthenticationStatus AuthenticationStatus,
    IReadOnlyList<RemoteShareAccessReport> Shares);

public sealed record RemoteLinuxRootAccessReport(
    string Root,
    bool Accessible,
    long DirectoriesVisited,
    long FilesSeen,
    long CandidatesFound,
    string? Error);

public sealed record RemoteLinuxTargetReport(
    string HostReference,
    string HostName,
    int Port,
    IReadOnlyList<string> IPv4Addresses,
    IReadOnlyList<string> IPv6Addresses,
    string AuthenticationMode,
    RemoteAuthenticationStatus AuthenticationStatus,
    string? HostKeySha256,
    IReadOnlyList<RemoteLinuxRootAccessReport> Roots);

public sealed record RootCoverage(
    string Root,
    bool Exists,
    bool Completed,
    long DirectoriesVisited,
    long FilesSeen,
    long CandidatesFound,
    long PolicyDirectoriesSkipped,
    long ReparseDirectoriesSkipped,
    long ReparseFilesSkipped,
    long Errors);

public sealed record ScanCoverage(
    IReadOnlyList<RootCoverage> Roots,
    long DirectoriesVisited,
    long FilesSeen,
    long CandidatesFound,
    long PolicyDirectoriesSkipped,
    long ReparseDirectoriesSkipped,
    long ReparseFilesSkipped)
{
    public static ScanCoverage Empty { get; } = new(
        Array.Empty<RootCoverage>(), 0, 0, 0, 0, 0, 0);
}

public sealed record ResourcePolicy(
    double MaxCpuPercent,
    double GlobalNetworkMbps,
    double PerHostNetworkMbps,
    int IoBufferKiB,
    int MaxAdaptiveDelayMilliseconds)
{
    public static ResourcePolicy Default { get; } = new(75, 80, 40, 256, 80);
}

public sealed record TraversalLimits(
    long MaxFiles,
    long MaxDirectories,
    int MaxDepth)
{
    public static TraversalLimits Default { get; } = new(5_000_000, 1_000_000, 128);
}

public sealed record ScanProgress(
    long FilesSeen,
    long DirectoriesVisited,
    long CandidatesFound,
    string CurrentDirectory,
    int AdaptiveDelayMilliseconds);

public sealed record MustCopyVolumeSummary(
    long FileCount,
    long EstimatedBytes,
    long ProjectSourceFiles,
    long ProjectSourceBytes,
    long StandaloneMustCopyFiles,
    long StandaloneMustCopyBytes,
    long StandaloneExplicitMustIncludeFiles,
    long StandaloneExplicitMustIncludeBytes,
    long StandaloneProtectedOfficeFiles,
    long StandaloneProtectedOfficeBytes,
    string Basis)
{
    public static MustCopyVolumeSummary Empty { get; } = new(0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        "No must-copy estimate is available for this manifest.");
}

public sealed record BackupInventory(
    string SourcePath,
    IReadOnlyList<string> CoveredPaths);

public sealed record BackupGapItem(
    string Kind,
    string Path,
    long? Size,
    BackupPriority Priority,
    string Category,
    bool Covered,
    string? CoveredBy);

public sealed record BackupGapSummary(
    bool InventoryProvided,
    int InventoryEntryCount,
    long CandidateBytes,
    long CoveredCandidateBytes,
    long UncoveredCandidateBytes,
    int CandidateCount,
    int CoveredCandidateCount,
    int UncoveredCandidateCount,
    int CriticalUncoveredCount,
    int HighUncoveredCount,
    int BackupSetCount,
    int CoveredBackupSetCount,
    int UncoveredBackupSetCount,
    IReadOnlyList<BackupGapItem> TopUncovered);

public sealed record ScanChange(
    string ChangeType,
    string Path,
    long? PreviousSize,
    long? CurrentSize,
    BackupPriority? PreviousPriority,
    BackupPriority? CurrentPriority,
    FileCategory? PreviousCategory,
    FileCategory? CurrentCategory);

public sealed record ScanDiffSummary(
    bool PreviousScanAvailable,
    DateTime? PreviousGeneratedAtUtc,
    string? PreviousManifestReference,
    int AddedCount,
    int RemovedCount,
    int ChangedCount,
    long AddedBytes,
    long RemovedBytes,
    IReadOnlyList<ScanChange> TopChanges);

public sealed record ReadinessFactor(
    string Name,
    int Score,
    int MaxScore,
    string Status,
    string Detail);

public sealed record BackupReadinessAssessment(
    int Score,
    string Grade,
    string Confidence,
    bool BackupInventoryProvided,
    int CriticalCandidateCount,
    int HighCandidateCount,
    int ProtectedOfficeCount,
    long CandidateBytes,
    IReadOnlyList<ReadinessFactor> Factors,
    IReadOnlyList<string> AttentionItems);

public sealed class DiscoveryManifest
{
    public string FormatVersion { get; init; } = "3.3";
    public string ApplicationVersion { get; init; } = "3.3.0";
    public string RuleSetVersion { get; init; } = "discover-only-3.3-linux-sftp-jvm-fastpath";
    public DateTime GeneratedAtUtc { get; init; } = DateTime.UtcNow;
    public HostIdentity ScannerHost { get; init; } = SourceIdentityProvider.GetScannerHostIdentity();
    public IReadOnlyList<SourceDescriptor> Sources { get; init; } = Array.Empty<SourceDescriptor>();
    public IReadOnlyList<RemoteTargetReport> RemoteTargets { get; init; } = Array.Empty<RemoteTargetReport>();
    public IReadOnlyList<RemoteLinuxTargetReport> RemoteLinuxTargets { get; init; } = Array.Empty<RemoteLinuxTargetReport>();
    public ContentInspectionProfile ContentInspectionProfile { get; init; } = ContentInspectionProfile.Balanced;
    public bool OfficeProtectionInspectionEnabled { get; init; } = true;
    public ResourcePolicy ResourcePolicy { get; init; } = ResourcePolicy.Default;
    public TraversalLimits TraversalLimits { get; init; } = TraversalLimits.Default;
    public PlatformTraversalOptions PlatformTraversal { get; init; } = PlatformTraversalOptions.Default;
    public ScanCoverage ScanCoverage { get; init; } = ScanCoverage.Empty;
    public IReadOnlyList<FileCandidate> Candidates { get; init; } = Array.Empty<FileCandidate>();
    public IReadOnlyList<BackupSet> BackupSets { get; init; } = Array.Empty<BackupSet>();
    public IReadOnlyList<string> Errors { get; init; } = Array.Empty<string>();
    public IReadOnlyList<ProjectVolumeStat> ProjectVolumes { get; init; } = Array.Empty<ProjectVolumeStat>();
    public ScanPerformanceSummary Performance { get; init; } = ScanPerformanceSummary.Empty;
    public MustCopyVolumeSummary MustCopyVolume { get; init; } = MustCopyVolumeSummary.Empty;

    public BackupGapSummary? BackupGap { get; set; }
    public ScanDiffSummary? Diff { get; set; }
    public BackupReadinessAssessment? Readiness { get; set; }
}
