using System.Text.Json;

namespace SmartBackupDiscovery;

public static class ManifestReader
{
    public static DiscoveryManifest Read(string path)
    {
        path = Path.GetFullPath(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 128 * 1024, FileOptions.SequentialScan);
        return JsonSerializer.Deserialize<DiscoveryManifest>(stream, ManifestWriter.Options)
               ?? throw new InvalidDataException($"Manifest is empty or invalid: {path}");
    }
}
