using System.Globalization;
using System.Net;
using System.Text;

namespace SmartBackupDiscovery;

public sealed record ManagementReportArtifacts(string HtmlPath, string PdfPath);

public static class ManagementReportWriter
{
    public static ManagementReportArtifacts Write(string reportDirectory, string manifestPath, DiscoveryManifest manifest, bool privacyMode)
    {
        string dir = Path.GetFullPath(reportDirectory);
        ManifestWriter.EnsureNoReparseAncestors(dir);
        Directory.CreateDirectory(dir);
        ManifestWriter.EnsureNoReparseAncestors(dir);

        string stem = Path.GetFileNameWithoutExtension(manifestPath);
        string htmlPath = Path.Combine(dir, stem + "-management-report.html");
        string pdfPath = Path.Combine(dir, stem + "-management-summary.pdf");
        WriteAtomicText(htmlPath, BuildHtml(manifest, privacyMode));
        MinimalPdfWriter.Write(pdfPath, BuildPdfLines(manifest, privacyMode));
        return new ManagementReportArtifacts(htmlPath, pdfPath);
    }

    private static string BuildHtml(DiscoveryManifest manifest, bool privacyMode)
    {
        BackupReadinessAssessment readiness = manifest.Readiness ?? BackupReadinessCalculator.Calculate(manifest, manifest.BackupGap);
        string E(string value) => WebUtility.HtmlEncode(value);
        string P(string path) => E(privacyMode ? MaskPath(path) : path);
        string scoreClass = readiness.Score >= 80 ? "good" : readiness.Score >= 60 ? "warn" : "bad";
        int linuxServiceSets = manifest.BackupSets.Count(x => x.Type == "LinuxServiceData");
        var sb = new StringBuilder(64 * 1024);
        sb.Append("""
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SmartBackupDiscovery Management Report</title>
<style>
:root{font-family:Segoe UI,Arial,sans-serif;color:#172033;background:#f3f5f8}body{margin:0}.page{max-width:1180px;margin:28px auto;padding:0 20px}.hero{background:#111827;color:white;padding:28px;border-radius:18px}.hero h1{margin:0 0 8px;font-size:29px}.muted{color:#64748b}.hero .muted{color:#cbd5e1}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin:18px 0}.card{background:white;border:1px solid #e5e7eb;border-radius:14px;padding:18px;box-shadow:0 2px 8px rgba(15,23,42,.04)}.metric{font-size:28px;font-weight:700}.score{font-size:54px;font-weight:800}.good{color:#15803d}.warn{color:#b45309}.bad{color:#b91c1c}table{width:100%;border-collapse:collapse;background:white;border-radius:12px;overflow:hidden}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid #e5e7eb;font-size:13px}th{background:#f8fafc}.section{margin-top:24px}.pill{display:inline-block;padding:4px 9px;border-radius:999px;background:#eef2ff;margin-right:6px;font-size:12px}.bar{height:8px;background:#e5e7eb;border-radius:99px;overflow:hidden}.bar>span{display:block;height:100%;background:#334155}.attention li{margin:6px 0}@media print{body{background:white}.page{max-width:none;margin:0}.card,.hero{box-shadow:none;break-inside:avoid}a{color:inherit;text-decoration:none}}
</style></head><body><div class="page">
""");
        sb.Append($"<div class=\"hero\"><h1>SmartBackupDiscovery Management Report</h1><div class=\"muted\">Generated {E(manifest.GeneratedAtUtc.ToString("u", CultureInfo.InvariantCulture))} · Scanner {E(manifest.ScannerHost.HostName)}</div></div>");

        sb.Append("<div class=\"grid\">");
        Card("Backup readiness", $"<div class=\"score {scoreClass}\">{readiness.Score}/100</div><div>Grade {E(readiness.Grade)} · Confidence {E(readiness.Confidence)}</div>");
        Card("Critical", $"<div class=\"metric\">{readiness.CriticalCandidateCount:N0}</div><div class=\"muted\">critical candidates</div>");
        Card("High priority", $"<div class=\"metric\">{readiness.HighCandidateCount:N0}</div><div class=\"muted\">high-priority candidates</div>");
        Card("Protected Office", $"<div class=\"metric\">{readiness.ProtectedOfficeCount:N0}</div><div class=\"muted\">encrypted/protected</div>");
        Card("Candidate bytes", $"<div class=\"metric\">{E(FormatBytes(readiness.CandidateBytes))}</div><div class=\"muted\">file candidates only</div>");
        Card("Must-copy estimate", $"<div class=\"metric\">{E(FormatBytes(manifest.MustCopyVolume.EstimatedBytes))}</div><div class=\"muted\">{manifest.MustCopyVolume.FileCount:N0} files, de-duplicated by project root</div>");
        Card("Logical sets", $"<div class=\"metric\">{manifest.BackupSets.Count:N0}</div><div class=\"muted\">projects / databases / Linux service sets</div>");
        sb.Append("</div>");

        sb.Append("<div class=\"section\"><h2>Must-copy volume</h2><div class=\"grid\">");
        Card("Project source trees", $"<div class=\"metric\">{E(FormatBytes(manifest.MustCopyVolume.ProjectSourceBytes))}</div><div class=\"muted\">{manifest.MustCopyVolume.ProjectSourceFiles:N0} retained files</div>");
        Card("Standalone critical/protected", $"<div class=\"metric\">{E(FormatBytes(manifest.MustCopyVolume.StandaloneMustCopyBytes))}</div><div class=\"muted\">{manifest.MustCopyVolume.StandaloneMustCopyFiles:N0} files</div>");
        Card("JVM projects", $"<div class=\"metric\">{manifest.Performance.JvmProjectsDetected:N0}</div><div class=\"muted\">marker/layout/source-root detection</div>");
        Card("Signature reads avoided", $"<div class=\"metric\">{manifest.Performance.SignatureProbesAvoided:N0}</div><div class=\"muted\">source/project fast path</div>");
        Card("Linux service sets", $"<div class=\"metric\">{linuxServiceSets:N0}</div><div class=\"muted\">application-aware backup required</div>");
        Card("Mount boundaries skipped", $"<div class=\"metric\">{manifest.Performance.MountBoundariesSkipped:N0}</div><div class=\"muted\">Linux default stays on selected filesystems</div>");
        sb.Append("</div><div class=\"card muted\">" + E(manifest.MustCopyVolume.Basis) + "</div></div>");

        sb.Append("<div class=\"section card\"><h2>Readiness factors</h2>");
        foreach (ReadinessFactor factor in readiness.Factors)
        {
            int pct = factor.MaxScore == 0 ? 0 : (int)Math.Round(100.0 * factor.Score / factor.MaxScore);
            sb.Append($"<div style=\"margin:14px 0\"><b>{E(factor.Name)}</b> <span class=\"pill\">{factor.Score}/{factor.MaxScore} · {E(factor.Status)}</span><div class=\"bar\"><span style=\"width:{pct}%\"></span></div><div class=\"muted\">{E(factor.Detail)}</div></div>");
        }
        sb.Append("</div>");

        if (readiness.AttentionItems.Count > 0)
        {
            sb.Append("<div class=\"section card\"><h2>Attention required</h2><ul class=\"attention\">");
            foreach (string item in readiness.AttentionItems) sb.Append($"<li>{E(item)}</li>");
            sb.Append("</ul></div>");
        }

        if (manifest.BackupGap is { } gap)
        {
            sb.Append("<div class=\"section\"><h2>Backup gap analysis</h2><div class=\"grid\">");
            Card("Covered candidate bytes", $"<div class=\"metric\">{E(FormatBytes(gap.CoveredCandidateBytes))}</div>");
            Card("Uncovered candidate bytes", $"<div class=\"metric\">{E(FormatBytes(gap.UncoveredCandidateBytes))}</div>");
            Card("Critical uncovered", $"<div class=\"metric\">{gap.CriticalUncoveredCount:N0}</div>");
            Card("Logical sets uncovered", $"<div class=\"metric\">{gap.UncoveredBackupSetCount:N0}</div>");
            sb.Append("</div>");
            if (gap.TopUncovered.Count > 0)
            {
                sb.Append("<table><thead><tr><th>Priority</th><th>Type</th><th>Path</th><th>Size</th></tr></thead><tbody>");
                foreach (BackupGapItem item in gap.TopUncovered)
                    sb.Append($"<tr><td>{E(item.Priority.ToString())}</td><td>{E(item.Category)}</td><td>{P(item.Path)}</td><td>{E(item.Size is null ? "logical set" : FormatBytes(item.Size.Value))}</td></tr>");
                sb.Append("</tbody></table>");
            }
            sb.Append("</div>");
        }

        if (manifest.Diff is { PreviousScanAvailable: true } diff)
        {
            sb.Append("<div class=\"section\"><h2>Changes since previous scan</h2><div class=\"grid\">");
            Card("Added", $"<div class=\"metric\">{diff.AddedCount:N0}</div><div class=\"muted\">{E(FormatBytes(diff.AddedBytes))}</div>");
            Card("Changed", $"<div class=\"metric\">{diff.ChangedCount:N0}</div>");
            Card("Removed", $"<div class=\"metric\">{diff.RemovedCount:N0}</div><div class=\"muted\">{E(FormatBytes(diff.RemovedBytes))}</div>");
            sb.Append("</div>");
            if (diff.TopChanges.Count > 0)
            {
                sb.Append("<table><thead><tr><th>Change</th><th>Path</th><th>Previous</th><th>Current</th></tr></thead><tbody>");
                foreach (ScanChange item in diff.TopChanges)
                    sb.Append($"<tr><td>{E(item.ChangeType)}</td><td>{P(item.Path)}</td><td>{E(item.PreviousSize is null ? "-" : FormatBytes(item.PreviousSize.Value))}</td><td>{E(item.CurrentSize is null ? "-" : FormatBytes(item.CurrentSize.Value))}</td></tr>");
                sb.Append("</tbody></table>");
            }
            sb.Append("</div>");
        }

        if (manifest.Candidates.Count > 0)
        {
            sb.Append("<div class=\"section\"><h2>Top backup candidates</h2><table><thead><tr><th>Priority</th><th>Category</th><th>Path</th><th>Size</th><th>Reason</th></tr></thead><tbody>");
            foreach (FileCandidate candidate in manifest.Candidates
                         .OrderByDescending(x => x.Priority)
                         .ThenByDescending(x => x.Score)
                         .Take(200))
            {
                string reason = candidate.Evidence.FirstOrDefault()?.Summary ?? candidate.ReasonCode ?? string.Empty;
                sb.Append($"<tr><td>{E(candidate.Priority.ToString())}</td><td>{E(candidate.Category.ToString())}</td><td>{P(candidate.Path)}</td><td>{E(FormatBytes(candidate.Size))}</td><td>{E(reason)}</td></tr>");
            }
            sb.Append("</tbody></table></div>");
        }

        sb.Append("<div class=\"section\"><h2>Remote targets</h2>");
        if (manifest.RemoteTargets.Count == 0 && manifest.RemoteLinuxTargets.Count == 0)
            sb.Append("<div class=\"card muted\">No remote targets were requested.</div>");
        if (manifest.RemoteTargets.Count > 0)
        {
            sb.Append("<h3>Windows SMB</h3><table><thead><tr><th>Host</th><th>Status</th><th>IPv4</th><th>Shares</th></tr></thead><tbody>");
            foreach (RemoteTargetReport target in manifest.RemoteTargets)
            {
                string shares = string.Join(", ", target.Shares.Select(s => $"{s.Share}:{(s.Connected ? "OK" : "FAIL")}"));
                sb.Append($"<tr><td>{E(target.HostReference)}</td><td>{E(target.AuthenticationStatus.ToString())}</td><td>{E(string.Join(", ", target.IPv4Addresses))}</td><td>{E(shares)}</td></tr>");
            }
            sb.Append("</tbody></table>");
        }
        if (manifest.RemoteLinuxTargets.Count > 0)
        {
            sb.Append("<h3>Linux SFTP</h3><table><thead><tr><th>Host</th><th>Status</th><th>Authentication</th><th>Host key</th><th>Roots</th></tr></thead><tbody>");
            foreach (RemoteLinuxTargetReport target in manifest.RemoteLinuxTargets)
            {
                string rootsText = string.Join(", ", target.Roots.Select(r => $"{(privacyMode ? MaskPath(r.Root) : r.Root)}:{(r.Accessible ? "OK" : "FAIL")}"));
                string hostKey = target.HostKeySha256 is null ? "unknown" : "SHA256:" + target.HostKeySha256;
                sb.Append($"<tr><td>{E(target.HostReference + ":" + target.Port)}</td><td>{E(target.AuthenticationStatus.ToString())}</td><td>{E(target.AuthenticationMode)}</td><td>{E(hostKey)}</td><td>{E(rootsText)}</td></tr>");
            }
            sb.Append("</tbody></table>");
        }
        sb.Append("</div>");

        sb.Append("<div class=\"section card muted\">This report is discovery-only. It does not copy files or prove recoverability. The must-copy figure is a metadata-based recommendation: detected project source trees exclude known generated/dependency directories, and standalone Critical/MustInclude/protected Office files are added without double-counting paths already inside those projects.</div>");
        sb.Append("</div></body></html>");
        return sb.ToString();

        void Card(string title, string body) => sb.Append($"<div class=\"card\"><div class=\"muted\">{E(title)}</div>{body}</div>");
    }

    private static IReadOnlyList<string> BuildPdfLines(DiscoveryManifest manifest, bool privacyMode)
    {
        BackupReadinessAssessment readiness = manifest.Readiness ?? BackupReadinessCalculator.Calculate(manifest, manifest.BackupGap);
        int linuxServiceSets = manifest.BackupSets.Count(x => x.Type == "LinuxServiceData");
        var lines = new List<string>
        {
            "SmartBackupDiscovery Management Summary",
            $"Generated: {manifest.GeneratedAtUtc:u}",
            $"Scanner: {manifest.ScannerHost.HostName}",
            "",
            $"Backup readiness: {readiness.Score}/100 (Grade {readiness.Grade}, confidence {readiness.Confidence})",
            $"Critical candidates: {readiness.CriticalCandidateCount}",
            $"High-priority candidates: {readiness.HighCandidateCount}",
            $"Protected/encrypted Office: {readiness.ProtectedOfficeCount}",
            $"Candidate bytes: {FormatBytes(readiness.CandidateBytes)}",
            $"Must-copy estimate: {FormatBytes(manifest.MustCopyVolume.EstimatedBytes)} ({manifest.MustCopyVolume.FileCount} files)",
            $"Project source volume: {FormatBytes(manifest.MustCopyVolume.ProjectSourceBytes)} ({manifest.MustCopyVolume.ProjectSourceFiles} files)",
            $"Standalone critical/protected: {FormatBytes(manifest.MustCopyVolume.StandaloneMustCopyBytes)} ({manifest.MustCopyVolume.StandaloneMustCopyFiles} files)",
            $"JVM projects detected: {manifest.Performance.JvmProjectsDetected}",
            $"Signature probes avoided: {manifest.Performance.SignatureProbesAvoided}",
            $"Logical backup sets: {manifest.BackupSets.Count}",
            $"Linux service-data sets: {linuxServiceSets}",
            $"Linux platform directories skipped: {manifest.Performance.LinuxPolicyDirectoriesSkipped}",
            $"Mount boundaries skipped: {manifest.Performance.MountBoundariesSkipped}",
            "",
            "Readiness factors:"
        };
        lines.AddRange(readiness.Factors.Select(f => $"- {f.Name}: {f.Score}/{f.MaxScore} [{f.Status}] {f.Detail}"));
        if (readiness.AttentionItems.Count > 0)
        {
            lines.Add("");
            lines.Add("Attention required:");
            lines.AddRange(readiness.AttentionItems.Select(x => "- " + x));
        }
        if (manifest.BackupGap is { } gap)
        {
            lines.Add("");
            lines.Add("Backup gap analysis:");
            lines.Add($"- Covered candidate bytes: {FormatBytes(gap.CoveredCandidateBytes)}");
            lines.Add($"- Uncovered candidate bytes: {FormatBytes(gap.UncoveredCandidateBytes)}");
            lines.Add($"- Critical uncovered candidates: {gap.CriticalUncoveredCount}");
            lines.Add($"- Uncovered logical sets: {gap.UncoveredBackupSetCount}");
            foreach (BackupGapItem item in gap.TopUncovered.Take(20))
                lines.Add($"  {item.Priority} {item.Category}: {(privacyMode ? MaskPath(item.Path) : item.Path)}");
        }
        if (manifest.Diff is { PreviousScanAvailable: true } diff)
        {
            lines.Add("");
            lines.Add("Changes since previous scan:");
            lines.Add($"- Added: {diff.AddedCount} ({FormatBytes(diff.AddedBytes)})");
            lines.Add($"- Changed: {diff.ChangedCount}");
            lines.Add($"- Removed: {diff.RemovedCount} ({FormatBytes(diff.RemovedBytes)})");
        }
        if (manifest.RemoteTargets.Count > 0 || manifest.RemoteLinuxTargets.Count > 0)
        {
            lines.Add("");
            lines.Add("Remote access:");
            lines.AddRange(manifest.RemoteTargets.Select(t => $"- Windows SMB {t.HostReference}: {t.AuthenticationStatus}"));
            lines.AddRange(manifest.RemoteLinuxTargets.Select(t => $"- Linux SFTP {t.HostReference}:{t.Port}: {t.AuthenticationStatus}, host key {(t.HostKeySha256 is null ? "unknown" : "SHA256:" + t.HostKeySha256)}"));
        }
        lines.Add("");
        lines.Add("Discovery-only report: no file content was copied or backed up by SmartBackupDiscovery. Remote Linux SFTP mode transfers directory/file metadata only and executes no shell commands.");
        return lines;
    }

    private static void WriteAtomicText(string path, string content)
    {
        string full = Path.GetFullPath(path);
        string parent = Path.GetDirectoryName(full) ?? Environment.CurrentDirectory;
        ManifestWriter.EnsureNoReparseAncestors(parent);
        Directory.CreateDirectory(parent);
        ManifestWriter.EnsureNoReparseAncestors(parent);
        if (File.Exists(full) && (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Refusing to overwrite a reparse-point report file.");
        string staged = Path.Combine(parent, $".sbd-report-{Guid.NewGuid():N}.tmp");
        try
        {
            File.WriteAllText(staged, content, new UTF8Encoding(false));
            File.Move(staged, full, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(staged)) File.Delete(staged); } catch { }
        }
    }

    internal static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB", "PB"];
        double value = Math.Max(0, bytes);
        int unit = 0;
        while (value >= 1024 && unit < units.Length - 1) { value /= 1024; unit++; }
        return $"{value:0.##} {units[unit]}";
    }

    internal static string MaskPath(string path)
    {
        bool windowsStyle = path.Contains('\\') || path.StartsWith(@"\\", StringComparison.Ordinal);
        char separator = windowsStyle ? '\\' : '/';
        string value = windowsStyle ? path.Replace('/', '\\') : path.Replace('\\', '/');
        string[] parts = value.Split(separator, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length <= 2) return value;
        for (int i = 1; i < parts.Length - 1; i++)
        {
            string p = parts[i];
            if (p.Length > 2) parts[i] = p[..1] + new string('*', Math.Min(6, p.Length - 1));
        }
        string prefix = windowsStyle
            ? (value.StartsWith(@"\\", StringComparison.Ordinal) ? @"\\" : string.Empty)
            : (value.StartsWith("/", StringComparison.Ordinal) ? "/" : string.Empty);
        return prefix + string.Join(separator, parts);
    }
}

internal static class MinimalPdfWriter
{
    public static void Write(string path, IReadOnlyList<string> sourceLines)
    {
        string full = Path.GetFullPath(path);
        string parent = Path.GetDirectoryName(full) ?? Environment.CurrentDirectory;
        ManifestWriter.EnsureNoReparseAncestors(parent);
        Directory.CreateDirectory(parent);
        ManifestWriter.EnsureNoReparseAncestors(parent);
        if (File.Exists(full) && (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Refusing to overwrite a reparse-point PDF file.");

        var wrapped = new List<string>();
        foreach (string line in sourceLines)
            wrapped.AddRange(Wrap(ToPdfSafeAscii(line), 92));
        const int linesPerPage = 50;
        var pages = wrapped.Chunk(linesPerPage).Select(x => x.ToArray()).ToArray();
        if (pages.Length == 0) pages = [Array.Empty<string>()];

        var objects = new Dictionary<int, byte[]>();
        int pageCount = pages.Length;
        int fontId = 3;
        var pageIds = new int[pageCount];
        var contentIds = new int[pageCount];
        for (int i = 0; i < pageCount; i++)
        {
            pageIds[i] = 4 + i * 2;
            contentIds[i] = 5 + i * 2;
        }

        objects[1] = Ascii($"<< /Type /Catalog /Pages 2 0 R >>");
        objects[2] = Ascii($"<< /Type /Pages /Count {pageCount} /Kids [{string.Join(" ", pageIds.Select(id => $"{id} 0 R"))}] >>");
        objects[fontId] = Ascii("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");

        for (int i = 0; i < pageCount; i++)
        {
            objects[pageIds[i]] = Ascii($"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 {fontId} 0 R >> >> /Contents {contentIds[i]} 0 R >>");
            var content = new StringBuilder("BT\n/F1 10 Tf\n50 790 Td\n14 TL\n");
            foreach (string line in pages[i])
                content.Append('(').Append(EscapePdfString(line)).Append(") Tj\nT*\n");
            content.Append("ET\n");
            byte[] payload = Ascii(content.ToString());
            objects[contentIds[i]] = Combine(Ascii($"<< /Length {payload.Length} >>\nstream\n"), payload, Ascii("endstream"));
        }

        string staged = Path.Combine(parent, $".sbd-pdf-{Guid.NewGuid():N}.tmp");
        try
        {
            using var stream = new FileStream(staged, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            WriteAscii(stream, "%PDF-1.4\n%SBD3\n");
            int maxId = objects.Keys.Max();
            var offsets = new long[maxId + 1];
            for (int id = 1; id <= maxId; id++)
            {
                offsets[id] = stream.Position;
                WriteAscii(stream, $"{id} 0 obj\n");
                stream.Write(objects[id]);
                WriteAscii(stream, "\nendobj\n");
            }
            long xref = stream.Position;
            WriteAscii(stream, $"xref\n0 {maxId + 1}\n0000000000 65535 f \n");
            for (int id = 1; id <= maxId; id++) WriteAscii(stream, $"{offsets[id]:D10} 00000 n \n");
            WriteAscii(stream, $"trailer\n<< /Size {maxId + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n");
            stream.Flush(flushToDisk: true);
            File.Move(staged, full, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(staged)) File.Delete(staged); } catch { }
        }
    }

    private static IEnumerable<string> Wrap(string line, int width)
    {
        if (line.Length == 0) { yield return string.Empty; yield break; }
        for (int i = 0; i < line.Length; i += width)
            yield return line.Substring(i, Math.Min(width, line.Length - i));
    }

    private static string ToPdfSafeAscii(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (char c in value) sb.Append(c is >= ' ' and <= '~' ? c : '?');
        return sb.ToString();
    }

    private static string EscapePdfString(string value) => value.Replace("\\", "\\\\").Replace("(", "\\(").Replace(")", "\\)");
    private static byte[] Ascii(string value) => Encoding.ASCII.GetBytes(value);
    private static void WriteAscii(Stream stream, string value) => stream.Write(Ascii(value));
    private static byte[] Combine(params byte[][] arrays)
    {
        int length = arrays.Sum(x => x.Length);
        byte[] result = new byte[length];
        int offset = 0;
        foreach (byte[] array in arrays) { Buffer.BlockCopy(array, 0, result, offset, array.Length); offset += array.Length; }
        return result;
    }
}
