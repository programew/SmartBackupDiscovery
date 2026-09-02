using System.IO.Compression;
using System.Text;

namespace SmartBackupDiscovery;

public sealed record BackupContentInspectionResult(
    InspectionStatus Status,
    long InspectedBytes,
    IReadOnlyList<DetectionEvidence> Evidence,
    FileCategory? SuggestedCategory = null,
    bool ProtectionDetected = false,
    string? ProtectionType = null,
    string? ReasonCode = null,
    string? Warning = null);

/// <summary>
/// Backup-oriented Office inspection only. It never searches document text for passwords,
/// tokens, connection strings or other secret values, and it never decrypts a document.
/// </summary>
public static class BackupContentDetector
{
    private static readonly byte[] OleSignature = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
    private static readonly HashSet<string> ModernOfficeExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"
    };
    private static readonly HashSet<string> LegacyOfficeExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".doc", ".xls", ".ppt"
    };

    public static BackupContentInspectionResult Analyze(
        string path,
        ContentInspectionProfile profile,
        ResourceGovernor? governor = null,
        string? remoteHost = null)
    {
        string ext = Path.GetExtension(path);
        if (!ModernOfficeExtensions.Contains(ext) && !LegacyOfficeExtensions.Contains(ext))
            return Unsupported();

        bool remote = path.StartsWith(@"\\", StringComparison.Ordinal);
        int xmlBudget = profile == ContentInspectionProfile.Deep ? 512 * 1024 : 128 * 1024;
        int legacyProbeBudget = profile == ContentInspectionProfile.Deep ? 2 * 1024 * 1024 : 512 * 1024;

        try
        {
            governor?.BeforeWork(remote);
            using var stream = new FileStream(
                path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                64 * 1024, FileOptions.SequentialScan);

            Span<byte> header = stackalloc byte[8];
            int headerRead = stream.Read(header);
            if (remote) governor?.AccountNetworkBytes(headerRead, remoteHost);
            long inspected = headerRead;

            if (ModernOfficeExtensions.Contains(ext) && headerRead == 8 && header.SequenceEqual(OleSignature))
            {
                return Protected(
                    "OFFICE_ENCRYPTED_PACKAGE",
                    "Encrypted Office package detected; the document cannot be inspected without its password/key and should be preserved carefully.",
                    "EncryptedOfficePackage",
                    inspected,
                    190);
            }

            if (LegacyOfficeExtensions.Contains(ext))
            {
                if (headerRead != 8 || !header.SequenceEqual(OleSignature))
                    return new BackupContentInspectionResult(InspectionStatus.Unsupported, inspected, Array.Empty<DetectionEvidence>());

                // Best-effort structural probe for Office crypto stream names in OLE directory metadata.
                stream.Position = 0;
                int remaining = legacyProbeBudget;
                byte[] buffer = new byte[Math.Min(64 * 1024, legacyProbeBudget)];
                using var collected = new MemoryStream(Math.Min(legacyProbeBudget, 256 * 1024));
                while (remaining > 0)
                {
                    int read = stream.Read(buffer, 0, Math.Min(buffer.Length, remaining));
                    if (read <= 0) break;
                    if (remote) governor?.AccountNetworkBytes(read, remoteHost);
                    collected.Write(buffer, 0, read);
                    inspected += read;
                    remaining -= read;
                }
                byte[] bytes = collected.ToArray();
                string unicode = Encoding.Unicode.GetString(bytes);
                string ascii = Encoding.ASCII.GetString(bytes);
                if (unicode.Contains("EncryptedPackage", StringComparison.OrdinalIgnoreCase) ||
                    unicode.Contains("EncryptionInfo", StringComparison.OrdinalIgnoreCase) ||
                    ascii.Contains("EncryptedPackage", StringComparison.OrdinalIgnoreCase) ||
                    ascii.Contains("EncryptionInfo", StringComparison.OrdinalIgnoreCase))
                {
                    return Protected(
                        "OFFICE_LEGACY_ENCRYPTION_METADATA",
                        "Office encryption metadata was detected in the legacy compound document; preserve the file and its unlock material separately.",
                        "LegacyOfficeEncryptionMetadata",
                        inspected,
                        180);
                }

                return new BackupContentInspectionResult(
                    InspectionStatus.Partial,
                    inspected,
                    Array.Empty<DetectionEvidence>(),
                    ReasonCode: "OFFICE_LEGACY_PROTECTION_UNKNOWN",
                    Warning: "Legacy Office protection/encryption status could not be determined reliably from a bounded structural probe.");
            }

            stream.Position = 0;
            if (headerRead < 4 || header[0] != (byte)'P' || header[1] != (byte)'K')
                return new BackupContentInspectionResult(InspectionStatus.Unsupported, inspected, Array.Empty<DetectionEvidence>());

            using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: false);

            if (ext.Equals(".docx", StringComparison.OrdinalIgnoreCase) || ext.Equals(".docm", StringComparison.OrdinalIgnoreCase))
            {
                var settings = archive.GetEntry("word/settings.xml");
                if (settings is null)
                    return new BackupContentInspectionResult(InspectionStatus.Full, inspected, Array.Empty<DetectionEvidence>());

                string text = ReadEntryTextBounded(settings, xmlBudget, out long bytes);
                if (remote) governor?.AccountNetworkBytes((int)Math.Min(int.MaxValue, bytes), remoteHost);
                inspected += bytes;
                if (text.Contains("documentProtection", StringComparison.OrdinalIgnoreCase))
                    return Protected(
                        "OFFICE_WORD_PROTECTION",
                        "Word document protection metadata detected; record this protected document as an important backup candidate.",
                        "WordDocumentProtection",
                        inspected,
                        165);

                return new BackupContentInspectionResult(InspectionStatus.Full, inspected, Array.Empty<DetectionEvidence>());
            }

            if (ext.Equals(".xlsx", StringComparison.OrdinalIgnoreCase) || ext.Equals(".xlsm", StringComparison.OrdinalIgnoreCase))
            {
                var kinds = new List<string>();
                var workbook = archive.GetEntry("xl/workbook.xml");
                if (workbook is not null)
                {
                    string text = ReadEntryTextBounded(workbook, xmlBudget, out long bytes);
                    if (remote) governor?.AccountNetworkBytes((int)Math.Min(int.MaxValue, bytes), remoteHost);
                    inspected += bytes;
                    if (text.Contains("workbookProtection", StringComparison.OrdinalIgnoreCase))
                        kinds.Add("WorkbookProtection");
                }

                int sheetBudget = profile == ContentInspectionProfile.Deep ? 64 : 16;
                foreach (var entry in archive.Entries.Where(e => e.FullName.StartsWith("xl/worksheets/", StringComparison.OrdinalIgnoreCase) && e.FullName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase)).Take(sheetBudget))
                {
                    string text = ReadEntryTextBounded(entry, xmlBudget, out long bytes);
                    if (remote) governor?.AccountNetworkBytes((int)Math.Min(int.MaxValue, bytes), remoteHost);
                    inspected += bytes;
                    if (text.Contains("sheetProtection", StringComparison.OrdinalIgnoreCase))
                    {
                        kinds.Add("SheetProtection");
                        break;
                    }
                }

                if (kinds.Count > 0)
                    return Protected(
                        "OFFICE_EXCEL_PROTECTION",
                        "Excel workbook/worksheet protection metadata detected; record this protected spreadsheet as an important backup candidate.",
                        string.Join("+", kinds.Distinct(StringComparer.OrdinalIgnoreCase)),
                        inspected,
                        165);

                return new BackupContentInspectionResult(InspectionStatus.Full, inspected, Array.Empty<DetectionEvidence>());
            }

            return new BackupContentInspectionResult(InspectionStatus.Full, inspected, Array.Empty<DetectionEvidence>());
        }
        catch (UnauthorizedAccessException)
        {
            return new BackupContentInspectionResult(InspectionStatus.AccessDenied, 0, Array.Empty<DetectionEvidence>());
        }
        catch (InvalidDataException)
        {
            return new BackupContentInspectionResult(InspectionStatus.Failed, 0, Array.Empty<DetectionEvidence>(),
                ReasonCode: "OFFICE_CONTAINER_INVALID",
                Warning: "Office container could not be parsed; the file is still retained by metadata rules when applicable.");
        }
        catch (IOException)
        {
            return new BackupContentInspectionResult(InspectionStatus.Failed, 0, Array.Empty<DetectionEvidence>(),
                ReasonCode: "OFFICE_READ_FAILED",
                Warning: "Office protection inspection failed because the file could not be read completely.");
        }
    }

    private static BackupContentInspectionResult Protected(string ruleId, string warning, string protectionType, long bytes, int score)
    {
        return new BackupContentInspectionResult(
            InspectionStatus.EncryptedOrProtected,
            bytes,
            new[] { new DetectionEvidence(ruleId, warning, "office-protection", score, EvidenceConfidence.High) },
            SuggestedCategory: FileCategory.Document,
            ProtectionDetected: true,
            ProtectionType: protectionType,
            ReasonCode: ruleId,
            Warning: warning);
    }

    private static BackupContentInspectionResult Unsupported() =>
        new(InspectionStatus.Unsupported, 0, Array.Empty<DetectionEvidence>());

    private static string ReadEntryTextBounded(ZipArchiveEntry entry, int maxBytes, out long bytesRead)
    {
        using var input = entry.Open();
        using var buffer = new MemoryStream(capacity: Math.Min(maxBytes, 64 * 1024));
        byte[] chunk = new byte[16 * 1024];
        int remaining = maxBytes;
        bytesRead = 0;
        while (remaining > 0)
        {
            int read = input.Read(chunk, 0, Math.Min(chunk.Length, remaining));
            if (read <= 0) break;
            buffer.Write(chunk, 0, read);
            remaining -= read;
            bytesRead += read;
        }
        return Encoding.UTF8.GetString(buffer.GetBuffer(), 0, checked((int)buffer.Length));
    }
}
