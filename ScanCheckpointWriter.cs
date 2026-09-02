using System.Text.Json;

namespace SmartBackupDiscovery;

internal sealed class ScanCheckpointWriter : IDisposable
{
    private static readonly JsonSerializerOptions CheckpointOptions = new(ManifestWriter.Options) { WriteIndented = false };
    private readonly string _path;
    private StreamWriter? _writer;
    private int _pending;
    private bool _completed;

    public ScanCheckpointWriter(string manifestPath)
    {
        _path = Path.GetFullPath(manifestPath) + ".scan-progress.jsonl";
        string parent = Path.GetDirectoryName(_path) ?? Environment.CurrentDirectory;
        ManifestWriter.EnsureNoReparseAncestors(parent);
        Directory.CreateDirectory(parent);
        ManifestWriter.EnsureNoReparseAncestors(parent);
        if (File.Exists(_path) && (File.GetAttributes(_path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Refusing to overwrite a reparse-point checkpoint file.");

        _writer = new StreamWriter(new FileStream(_path, FileMode.Create, FileAccess.Write, FileShare.Read, 64 * 1024, FileOptions.SequentialScan));
        _writer.WriteLine(JsonSerializer.Serialize(new { type = "scanCheckpoint", formatVersion = "3.4", startedAtUtc = DateTime.UtcNow }, CheckpointOptions));
        _writer.Flush();
    }

    public string CheckpointPath => _path;

    public void Append(FileCandidate candidate)
    {
        if (_writer is null || _completed) return;
        _writer.WriteLine(JsonSerializer.Serialize(new
        {
            type = "candidate",
            candidate.Path,
            candidate.Size,
            candidate.LastWriteTimeUtc,
            candidate.Score,
            candidate.Priority,
            candidate.Category,
            candidate.MustInclude,
            candidate.InspectionStatus,
            candidate.InspectedBytes,
            candidate.ReasonCode,
            candidate.Warning,
            candidate.ProtectionDetected,
            candidate.ProtectionType
        }, CheckpointOptions));
        if (++_pending >= 250)
        {
            _writer.Flush();
            _pending = 0;
        }
    }

    public void Complete()
    {
        if (_completed) return;
        _completed = true;
        DisposeWriter();
        try { File.Delete(_path); } catch { }
    }

    public void Dispose() => DisposeWriter();

    private void DisposeWriter()
    {
        var writer = Interlocked.Exchange(ref _writer, null);
        if (writer is null) return;
        try { writer.Flush(); } finally { writer.Dispose(); }
    }
}
