using System.Text;

namespace SmartBackupDiscovery;

public sealed record SignatureResult(
    FileCategory? SuggestedCategory,
    IReadOnlyList<DetectionEvidence> Evidence,
    long InspectedBytes);

public static class FileSignatureDetector
{
    private static readonly byte[] OleSignature = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };

    public static SignatureResult Analyze(string path, ResourceGovernor? governor = null, string? remoteHost = null)
    {
        try
        {
            bool remote = path.StartsWith(@"\\", StringComparison.Ordinal);
            governor?.BeforeWork(remote);
            using var handle = File.OpenHandle(
                path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                FileOptions.RandomAccess);
            Span<byte> header = stackalloc byte[512];
            int read = RandomAccess.Read(handle, header, 0);
            if (remote)
                governor?.AccountNetworkBytes(read, remoteHost);
            var data = header[..read];

            if (read >= 16 && Encoding.ASCII.GetString(data[..16]).StartsWith("SQLite format 3", StringComparison.Ordinal))
                return Match(FileCategory.Database, "SIG_SQLITE", "SQLite database signature", 190, read, true);

            if (read >= 5 && Encoding.ASCII.GetString(data[..5]).Equals("%PDF-", StringComparison.Ordinal))
                return Match(FileCategory.Document, "SIG_PDF", "PDF document signature", 115, read, false);

            if (read >= 8 && data[..8].SequenceEqual(OleSignature))
                return Match(null, "SIG_OLE", "OLE compound document signature", 35, read, false);

            if (read >= 4 && data[0] == (byte)'P' && data[1] == (byte)'K')
                return Match(null, "SIG_ZIP", "ZIP/OpenXML container signature", 20, read, false);

            return new SignatureResult(null, Array.Empty<DetectionEvidence>(), read);
        }
        catch
        {
            return new SignatureResult(null, Array.Empty<DetectionEvidence>(), 0);
        }
    }

    private static SignatureResult Match(FileCategory? category, string id, string summary, int score, long bytes, bool mustInclude)
        => new(category, new[] { new DetectionEvidence(id, summary, "signature", score, EvidenceConfidence.High, mustInclude) }, bytes);
}
