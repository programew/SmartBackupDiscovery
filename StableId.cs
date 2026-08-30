using System.Security.Cryptography;
using System.Text;

namespace SmartBackupDiscovery;

public static class StableId
{
    public static string Hash12(string value)
    {
        byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value.Trim().ToLowerInvariant()));
        return Convert.ToHexString(bytes.AsSpan(0, 6)).ToLowerInvariant();
    }
}
