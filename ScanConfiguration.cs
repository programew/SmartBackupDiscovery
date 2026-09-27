using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SmartBackupDiscovery;

// The JSON contains targets and policies. Optional passwords use a portable,
// passphrase-encrypted envelope; the passphrase is never written to the file.
public sealed class ScanConfiguration
{
    public int FormatVersion { get; set; } = 2;
    public DiscoverConfiguration Discover { get; set; } = new();
    public NetworkConfiguration Network { get; set; } = new();
    public ProtectedPasswords Passwords { get; set; } = new();

    [JsonIgnore]
    internal string BaseDirectory { get; private set; } = Environment.CurrentDirectory;

    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "SmartBackupDiscovery", "settings.json");

    public static ScanConfiguration Load(string path)
    {
        path = Path.GetFullPath(Environment.ExpandEnvironmentVariables(path));
        if (new FileInfo(path).Length > 1_048_576)
            throw new InvalidDataException("Configuration exceeds the 1 MiB limit.");
        ScanConfiguration config = JsonSerializer.Deserialize<ScanConfiguration>(File.ReadAllText(path), ManifestWriter.Options)
            ?? throw new InvalidDataException("Configuration is empty.");
        if (config.FormatVersion != 2 || config.Discover is null || config.Network is null || config.Passwords is null)
            throw new InvalidDataException("Unsupported settings format. Create a new portable configuration and re-enter credentials; Windows-bound encrypted passwords cannot be migrated automatically.");
        PortableSecretProtector.Validate(config.Passwords);
        config.BaseDirectory = Path.GetDirectoryName(path)!;
        return config;
    }

    public static void Save(string path, ScanConfiguration config)
    {
        if (config.FormatVersion != 2 || config.Discover is null || config.Network is null || config.Passwords is null)
            throw new InvalidDataException("Cannot save an invalid portable configuration.");
        PortableSecretProtector.Validate(config.Passwords);
        path = Path.GetFullPath(Environment.ExpandEnvironmentVariables(path));
        string parent = Path.GetDirectoryName(path) ?? Environment.CurrentDirectory;
        ManifestWriter.EnsureNoReparseAncestors(parent);
        Directory.CreateDirectory(parent);
        ManifestWriter.EnsureNoReparseAncestors(parent);
        if (File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Refusing to replace a symbolic-link configuration file.");

        string staged = Path.Combine(parent, $".sbd-settings-{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(staged, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                       16 * 1024, FileOptions.WriteThrough))
            {
                JsonSerializer.Serialize(stream, config, ManifestWriter.Options);
                stream.Flush(flushToDisk: true);
            }
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(staged, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            File.Move(staged, path, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(staged)) File.Delete(staged); } catch { }
        }
    }

    public static (string[] Arguments, ScanConfiguration? Configuration) ExpandArguments(string[] args)
    {
        if (args.Length == 0) return (args, null);
        string command = args[0].ToLowerInvariant();
        if (command is not ("discover" or "scan" or "network-discover" or "network-inventory"))
            return (args, null);

        var userArgs = new List<string> { args[0] };
        string? path = null;
        for (int i = 1; i < args.Length; i++)
        {
            if (args[i].Equals("--config", StringComparison.OrdinalIgnoreCase))
            {
                if (path is not null || i + 1 == args.Length || args[i + 1].StartsWith("--", StringComparison.Ordinal))
                    throw new ArgumentException("Provide exactly one --config <path>.");
                path = args[++i];
            }
            else userArgs.Add(args[i]);
        }
        if (path is null) return (args, null);

        string fullPath = Path.GetFullPath(Environment.ExpandEnvironmentVariables(path));
        ScanConfiguration config = Load(fullPath);
        bool network = command is "network-discover" or "network-inventory";
        var defaults = config.ToArguments(network, Path.GetDirectoryName(fullPath)!);
        if (network && config.Network.Authorized && userArgs.Contains("--cidr", StringComparer.OrdinalIgnoreCase) &&
            !userArgs.Contains("--authorized-scope", StringComparer.OrdinalIgnoreCase))
            throw new ArgumentException("Additional command-line CIDRs require an explicit --authorized-scope acknowledgement.");
        return (new[] { args[0] }.Concat(defaults).Concat(userArgs.Skip(1)).ToArray(), config);
    }

    internal List<string> FileArguments() => ToArguments(false, BaseDirectory);

    private List<string> ToArguments(bool networkMode, string baseDirectory)
    {
        var result = new List<string>();
        static void Add(List<string> result, string option, string? value)
        {
            if (!string.IsNullOrWhiteSpace(value)) { result.Add(option); result.Add(value); }
        }
        static bool ForeignWindowsPath(string value) => !OperatingSystem.IsWindows() &&
            (value.Length >= 3 && char.IsAsciiLetter(value[0]) && value[1] == ':' && (value[2] is '\\' or '/') ||
             value.StartsWith(@"\\", StringComparison.Ordinal));
        static string? Resolve(string? value, string baseDirectory)
        {
            if (string.IsNullOrWhiteSpace(value)) return null;
            if (ForeignWindowsPath(value))
            {
                Console.Error.WriteLine("Settings contain a Windows-specific path; skipping it on Linux. Supply a local path with a CLI option if required.");
                return null;
            }
            return Path.GetFullPath(Environment.ExpandEnvironmentVariables(value), baseDirectory);
        }
        static IEnumerable<string> Values(IEnumerable<string>? values) => values ?? Array.Empty<string>();
        if (networkMode)
        {
            if (Network.AutoStartFileDiscovery) result.Add("--auto-discover");
            foreach (string cidr in Values(Network.Cidrs)) Add(result, "--cidr", cidr);
            foreach (string cidr in Values(Network.Exclusions)) Add(result, "--exclude-cidr", cidr);
            if (Network.Authorized && Network.Cidrs?.Count > 0) result.Add("--authorized-scope");
            Add(result, "--output", Resolve(Network.Output, baseDirectory));
            Add(result, "--max-hosts", Network.MaxHosts.ToString(CultureInfo.InvariantCulture));
            Add(result, "--network-concurrency", Network.Concurrency.ToString(CultureInfo.InvariantCulture));
            Add(result, "--max-probes-per-second", Network.Rate.ToString(CultureInfo.InvariantCulture));
            Add(result, "--probe-timeout-ms", Network.TimeoutMilliseconds.ToString(CultureInfo.InvariantCulture));
            Add(result, "--max-cpu-percent", Network.MaxCpuPercent.ToString(CultureInfo.InvariantCulture));
            Add(result, "--network-limit-mbps", Network.NetworkMbps.ToString(CultureInfo.InvariantCulture));
        }
        else
        {
            foreach (string root in Values(Discover.LocalRoots)) Add(result, "--root", Resolve(root, baseDirectory));
            if (OperatingSystem.IsWindows())
            {
                foreach (string host in Values(Discover.WindowsHosts)) Add(result, "--host", host);
                Add(result, "--hosts-file", Resolve(Discover.WindowsHostsFile, baseDirectory));
                foreach (string share in Values(Discover.WindowsShares)) Add(result, "--remote-share", share);
                Add(result, "--username", Discover.WindowsUsername);
            }
            else if (Discover.WindowsHosts?.Count > 0 || !string.IsNullOrWhiteSpace(Discover.WindowsHostsFile))
                Console.Error.WriteLine("Skipping Windows SMB targets from settings on Linux; SMB discovery requires Windows.");
            foreach (string host in Values(Discover.LinuxHosts)) Add(result, "--linux-host", host);
            Add(result, "--linux-hosts-file", Resolve(Discover.LinuxHostsFile, baseDirectory));
            foreach (string root in Values(Discover.LinuxRoots)) Add(result, "--linux-root", root);
            Add(result, "--linux-username", Discover.LinuxUsername);
            Add(result, "--ssh-port", Discover.SshPort.ToString(CultureInfo.InvariantCulture));
            Add(result, "--ssh-host-key-sha256", Discover.SshFingerprint);
            if (Discover.SshTrustOnFirstUse) result.Add("--ssh-trust-on-first-use");
            Add(result, "--backup-inventory", Resolve(Discover.BackupInventory, baseDirectory));
            Add(result, "--manifest", Resolve(Discover.Manifest, baseDirectory));
            Add(result, "--max-cpu-percent", Discover.MaxCpuPercent.ToString(CultureInfo.InvariantCulture));
            Add(result, "--network-limit-mbps", Discover.NetworkMbps.ToString(CultureInfo.InvariantCulture));
            if (Discover.PrivacyMode) result.Add("--privacy-mode");
        }
        return result;
    }
}

public sealed class DiscoverConfiguration
{
    public List<string> LocalRoots { get; set; } = new();
    public List<string> WindowsHosts { get; set; } = new();
    public string? WindowsHostsFile { get; set; }
    public List<string> WindowsShares { get; set; } = new();
    public string? WindowsUsername { get; set; }
    public List<string> LinuxHosts { get; set; } = new();
    public string? LinuxHostsFile { get; set; }
    public List<string> LinuxRoots { get; set; } = new();
    public string? LinuxUsername { get; set; }
    public int SshPort { get; set; } = 22;
    public string? SshFingerprint { get; set; }
    public bool SshTrustOnFirstUse { get; set; }
    public string? BackupInventory { get; set; }
    public string? Manifest { get; set; }
    public int MaxCpuPercent { get; set; } = 75;
    public int NetworkMbps { get; set; } = 80;
    public bool PrivacyMode { get; set; }
}

public sealed class NetworkConfiguration
{
    public bool AutoStartFileDiscovery { get; set; }
    public List<string> Cidrs { get; set; } = new();
    public List<string> Exclusions { get; set; } = new();
    public bool Authorized { get; set; }
    public string? Output { get; set; }
    public int MaxHosts { get; set; } = 4096;
    public int Concurrency { get; set; } = 32;
    public int Rate { get; set; } = 64;
    public int TimeoutMilliseconds { get; set; } = 600;
    public int MaxCpuPercent { get; set; } = 75;
    public int NetworkMbps { get; set; } = 80;
}

public sealed class ProtectedPasswords
{
    public string? Algorithm { get; set; }
    public int Iterations { get; set; }
    public string? Salt { get; set; }
    public string? Nonce { get; set; }
    public string? Ciphertext { get; set; }
    public string? Tag { get; set; }

    [JsonIgnore]
    public bool HasSecrets => !string.IsNullOrWhiteSpace(Ciphertext);
}

internal sealed class CredentialPayload
{
    public string? WindowsPassword { get; set; }
    public string? LinuxPassword { get; set; }
}

internal static class PortableSecretProtector
{
    private const string Algorithm = "PBKDF2-HMAC-SHA256/AES-256-GCM";
    private const int Iterations = 600_000;
    private const int SaltSize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private static readonly byte[] Purpose = Encoding.UTF8.GetBytes("SmartBackupDiscovery.settings.credentials.v2");

    public static ProtectedPasswords Protect(CredentialPayload credentials, string passphrase)
    {
        if (string.IsNullOrWhiteSpace(passphrase) || passphrase.Length < 12)
            throw new ArgumentException("Use a configuration passphrase of at least 12 characters.");
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] plain = JsonSerializer.SerializeToUtf8Bytes(credentials, ManifestWriter.Options);
        byte[] cipher = new byte[plain.Length];
        byte[] tag = new byte[TagSize];
        byte[] key = DeriveKey(passphrase, salt, Iterations);
        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Encrypt(nonce, plain, cipher, tag, Purpose);
            return new ProtectedPasswords
            {
                Algorithm = Algorithm,
                Iterations = Iterations,
                Salt = Convert.ToBase64String(salt),
                Nonce = Convert.ToBase64String(nonce),
                Ciphertext = Convert.ToBase64String(cipher),
                Tag = Convert.ToBase64String(tag)
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    public static CredentialPayload Unprotect(ProtectedPasswords envelope, string passphrase)
    {
        Validate(envelope);
        if (!envelope.HasSecrets) return new CredentialPayload();
        if (string.IsNullOrEmpty(passphrase))
            throw new ArgumentException("The configuration passphrase is required to unlock saved passwords.");
        byte[] salt = Convert.FromBase64String(envelope.Salt!);
        byte[] nonce = Convert.FromBase64String(envelope.Nonce!);
        byte[] cipher = Convert.FromBase64String(envelope.Ciphertext!);
        byte[] tag = Convert.FromBase64String(envelope.Tag!);
        byte[] plain = new byte[cipher.Length];
        byte[] key = DeriveKey(passphrase, salt, envelope.Iterations);
        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, cipher, tag, plain, Purpose);
            return JsonSerializer.Deserialize<CredentialPayload>(plain, ManifestWriter.Options)
                ?? throw new InvalidDataException("Encrypted configuration credentials are empty.");
        }
        catch (CryptographicException ex)
        {
            throw new InvalidOperationException("Incorrect configuration passphrase or damaged encrypted credentials.", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    public static void Validate(ProtectedPasswords envelope)
    {
        if (!envelope.HasSecrets)
        {
            if (envelope.Algorithm is not null || envelope.Iterations != 0 || envelope.Salt is not null ||
                envelope.Nonce is not null || envelope.Tag is not null)
                throw new InvalidDataException("Incomplete encrypted credentials in the settings file.");
            return;
        }
        if (envelope.Algorithm != Algorithm || envelope.Iterations is < 600_000 or > 2_000_000 ||
            string.IsNullOrWhiteSpace(envelope.Salt) || string.IsNullOrWhiteSpace(envelope.Nonce) ||
            string.IsNullOrWhiteSpace(envelope.Tag))
            throw new InvalidDataException("Unsupported or incomplete encrypted credentials.");
        try
        {
            if (Convert.FromBase64String(envelope.Salt).Length != SaltSize ||
                Convert.FromBase64String(envelope.Nonce).Length != NonceSize ||
                Convert.FromBase64String(envelope.Tag).Length != TagSize ||
                Convert.FromBase64String(envelope.Ciphertext!).Length is < 1 or > 65_536)
                throw new InvalidDataException("Invalid encrypted credential lengths.");
        }
        catch (FormatException ex)
        {
            throw new InvalidDataException("Invalid Base64 in encrypted credentials.", ex);
        }
    }

    private static byte[] DeriveKey(string passphrase, byte[] salt, int iterations)
    {
        byte[] passwordBytes = Encoding.UTF8.GetBytes(passphrase.Normalize(NormalizationForm.FormC));
        try { return Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, iterations, HashAlgorithmName.SHA256, 32); }
        finally { CryptographicOperations.ZeroMemory(passwordBytes); }
    }
}
