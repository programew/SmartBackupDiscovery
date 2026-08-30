using System.Net;
using System.Text;

namespace SmartBackupDiscovery;

public sealed record ManagementReportArtifacts(string HtmlPath, string PdfPath);

public static class ManagementReportWriter
{
    public static ManagementReportArtifacts Write(string outputDirectory, string manifestPath, DiscoveryManifest manifest, bool privacyMode)
    {
        string dir = Path.GetFullPath(outputDirectory);
        ManifestWriter.EnsureNoReparseAncestors(dir);
        Directory.CreateDirectory(dir);
        string htmlPath = Path.Combine(dir, "SmartBackupDiscovery-report.html");
        string pdfPath = Path.Combine(dir, "SmartBackupDiscovery-summary.pdf");
        string E(string value) => WebUtility.HtmlEncode(privacyMode ? Mask(value) : value);
        string bytes(long value) => FormatBytes(value);
        var sb = new StringBuilder();
        sb.Append("<!doctype html><html><head><meta charset=\"utf-8\"><title>SmartBackupDiscovery Report</title><style>body{font-family:system-ui,Arial;margin:36px;color:#1f2937}h1,h2{color:#111827}.cards{display:flex;gap:14px;flex-wrap:wrap}.card{border:1px solid #ddd;border-radius:10px;padding:14px;min-width:150px}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ddd;padding:7px;text-align:left}code{font-size:.9em}</style></head><body>");
        sb.Append($"<h1>SmartBackupDiscovery</h1><p>Generated {manifest.GeneratedAtUtc:u}</p><div class=\"cards\">");
        Card("Readiness", manifest.Readiness is null ? "n/a" : $"{manifest.Readiness.Score}/100 ({manifest.Readiness.Grade})");
        Card("Candidates", manifest.Candidates.Count.ToString());
        Card("Candidate volume", bytes(SizeMath.SumCandidateBytes(manifest.Candidates)));
        Card("Must-copy", $"{manifest.MustCopyVolume.FileCount} / {bytes(manifest.MustCopyVolume.EstimatedBytes)}");
        Card("Projects", manifest.ProjectVolumes.Count.ToString());
        Card("Linux service sets", manifest.BackupSets.Count(x => x.Type == "LinuxServiceData").ToString());
        sb.Append("</div>");
        if (manifest.Readiness is not null)
        {
            sb.Append("<h2>Attention</h2><ul>");
            foreach (string item in manifest.Readiness.AttentionItems) sb.Append($"<li>{E(item)}</li>");
            sb.Append("</ul>");
        }
        if (manifest.BackupGap is { InventoryProvided: true } gap)
            sb.Append($"<h2>Backup gap</h2><p>Covered {gap.CoveredCandidateCount}/{gap.CandidateCount} candidates; uncovered {bytes(gap.UncoveredCandidateBytes)}; critical uncovered {gap.CriticalUncoveredCount}.</p>");
        if (manifest.Diff is { PreviousScanAvailable: true } diff)
            sb.Append($"<h2>Change since previous scan</h2><p>Added {diff.AddedCount}, changed {diff.ChangedCount}, removed {diff.RemovedCount}.</p>");
        sb.Append("<h2>Top candidates</h2><table><tr><th>Priority</th><th>Category</th><th>Size</th><th>Path</th><th>Reason</th></tr>");
        foreach (FileCandidate c in manifest.Candidates.OrderByDescending(x => x.Score).Take(200))
            sb.Append($"<tr><td>{c.Priority}</td><td>{c.Category}</td><td>{bytes(c.Size)}</td><td><code>{E(c.Path)}</code></td><td>{E(c.ReasonCode ?? string.Join(", ", c.Evidence.Select(x => x.RuleId)))}</td></tr>");
        sb.Append("</table><p><small>Discover-only assessment. SmartBackupDiscovery does not perform backups or modify discovered files.</small></p></body></html>");
        File.WriteAllText(htmlPath, sb.ToString(), new UTF8Encoding(false));
        WriteSimplePdf(pdfPath, manifest, privacyMode);
        return new ManagementReportArtifacts(htmlPath, pdfPath);

        void Card(string title, string value) => sb.Append($"<div class=\"card\"><b>{E(title)}</b><br>{E(value)}</div>");
    }

    private static void WriteSimplePdf(string path, DiscoveryManifest manifest, bool privacy)
    {
        string[] lines =
        {
            "SmartBackupDiscovery Management Summary",
            $"Generated: {manifest.GeneratedAtUtc:u}",
            $"Readiness: {(manifest.Readiness is null ? "n/a" : manifest.Readiness.Score + "/100 " + manifest.Readiness.Grade)}",
            $"Candidates: {manifest.Candidates.Count} ({FormatBytes(SizeMath.SumCandidateBytes(manifest.Candidates))})",
            $"Must-copy estimate: {manifest.MustCopyVolume.FileCount} files / {FormatBytes(manifest.MustCopyVolume.EstimatedBytes)}",
            $"Projects: {manifest.ProjectVolumes.Count}",
            $"Errors: {manifest.Errors.Count}",
            "Discover-only: no files are copied or modified."
        };
        var content = new StringBuilder("BT /F1 12 Tf 50 780 Td ");
        foreach (string line in lines) content.Append('(').Append(PdfEscape(line)).Append(") Tj 0 -20 Td ");
        content.Append("ET");
        byte[] stream = Encoding.ASCII.GetBytes(content.ToString());
        var objects = new[]
        {
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
            $"<< /Length {stream.Length} >>\nstream\n{Encoding.ASCII.GetString(stream)}\nendstream",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
        };
        using var ms = new MemoryStream(); using var w = new StreamWriter(ms, Encoding.ASCII, 1024, true) { NewLine = "\n" };
        w.Write("%PDF-1.4\n"); w.Flush(); var offsets = new List<long> { 0 };
        for (int i = 0; i < objects.Length; i++) { offsets.Add(ms.Position); w.Write($"{i + 1} 0 obj\n{objects[i]}\nendobj\n"); w.Flush(); }
        long xref = ms.Position; w.Write($"xref\n0 {objects.Length + 1}\n0000000000 65535 f \n");
        for (int i = 1; i < offsets.Count; i++) w.Write($"{offsets[i]:0000000000} 00000 n \n");
        w.Write($"trailer << /Size {objects.Length + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n"); w.Flush(); File.WriteAllBytes(path, ms.ToArray());
    }

    private static string PdfEscape(string s) => new string(s.Select(ch => ch is >= ' ' and <= '~' ? ch : '?').ToArray()).Replace("\\", "\\\\").Replace("(", "\\(").Replace(")", "\\)");
    private static string Mask(string s) => s.Length < 5 ? "***" : s[..Math.Min(3, s.Length)] + "***" + s[^Math.Min(2, s.Length)..];
    private static string FormatBytes(long bytes) { string[] u = ["B","KB","MB","GB","TB","PB"]; double v = Math.Max(0, bytes); int i = 0; while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; } return $"{v:0.##} {u[i]}"; }
}
