using System.Text.Json;
using System.Text.Json.Serialization;

namespace SmartBackupDiscovery;

public static class ManifestWriter
{
    internal static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() }
    };

    public static void WriteDiscovery(string path, DiscoveryManifest manifest)
    {
        path = Path.GetFullPath(path);
        string parent = Path.GetDirectoryName(path) ?? Environment.CurrentDirectory;
        EnsureNoReparseAncestors(parent);
        Directory.CreateDirectory(parent);
        EnsureNoReparseAncestors(parent);
        if (File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Refusing to overwrite a reparse-point manifest file.");

        string staged = Path.Combine(parent, $".sbd-manifest-{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(staged, FileMode.CreateNew, FileAccess.Write, FileShare.None, 128 * 1024,
                       FileOptions.SequentialScan | FileOptions.WriteThrough))
            {
                JsonSerializer.Serialize(stream, manifest, Options);
                stream.Flush(flushToDisk: true);
            }
            File.Move(staged, path, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(staged)) File.Delete(staged); } catch { }
        }
    }

    internal static void EnsureNoReparseAncestors(string path)
    {
        string current = Path.GetFullPath(path);
        while (!string.IsNullOrWhiteSpace(current))
        {
            if (Directory.Exists(current) && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new IOException($"Output path contains a reparse-point component: {current}");
            string? parent = Path.GetDirectoryName(current.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
            if (string.IsNullOrWhiteSpace(parent) || parent.Equals(current, PathRules.Comparison))
                break;
            current = parent;
        }
    }
}
