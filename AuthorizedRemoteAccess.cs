using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace SmartBackupDiscovery;

public sealed record RemoteTargetSpec(string Host, IReadOnlyList<string> Shares);

public sealed class AuthorizedRemoteAccess : IDisposable
{
    private const int ResourceTypeDisk = 1;
    private const int ErrorSessionCredentialConflict = 1219;

    private readonly List<string> _connectionsCreated = new();
    private bool _disposed;

    public RemoteAccessResult Connect(
        IReadOnlyList<RemoteTargetSpec> targets,
        string username,
        string password,
        int hostDelayMilliseconds)
    {
        if (!OperatingSystem.IsWindows())
        {
            var unsupported = targets.Select(t => BuildUnsupportedReport(t)).ToArray();
            return new RemoteAccessResult(
                Array.Empty<string>(),
                unsupported,
                new[] { "Credentialed Authorized Remote Discover requires Windows SMB/WNet. On non-Windows systems, mount the share first and use --root." });
        }

        var roots = new List<string>();
        var reports = new List<RemoteTargetReport>();
        var errors = new List<string>();

        for (int targetIndex = 0; targetIndex < targets.Count; targetIndex++)
        {
            RemoteTargetSpec target = targets[targetIndex];
            if (targetIndex > 0 && hostDelayMilliseconds > 0)
                Thread.Sleep(hostDelayMilliseconds);

            ResolveHost(target.Host, out string hostName, out var v4, out var v6);
            var shareReports = new List<RemoteShareAccessReport>();
            int connectedCount = 0;

            foreach (string share in target.Shares)
            {
                string remoteRoot = $@"\\{target.Host}\{share}";
                int code = ConnectShare(remoteRoot, username, password);
                if (code == 0)
                {
                    connectedCount++;
                    roots.Add(remoteRoot);
                    _connectionsCreated.Add(remoteRoot);
                    shareReports.Add(new RemoteShareAccessReport(share, remoteRoot, true, 0, null));
                    continue;
                }

                string message = code == ErrorSessionCredentialConflict
                    ? "Windows already has a connection to this server using different credentials (error 1219). Existing connections were not modified."
                    : new Win32Exception(code).Message;

                shareReports.Add(new RemoteShareAccessReport(share, remoteRoot, false, code, message));
                errors.Add($"Remote access failed for {remoteRoot}: {message} (code {code}).");
            }

            RemoteAuthenticationStatus status = connectedCount switch
            {
                0 => RemoteAuthenticationStatus.Failed,
                _ when connectedCount == target.Shares.Count => RemoteAuthenticationStatus.Succeeded,
                _ => RemoteAuthenticationStatus.Partial
            };

            reports.Add(new RemoteTargetReport(
                target.Host,
                hostName,
                v4,
                v6,
                "ExplicitCredential",
                status,
                shareReports));
        }

        return new RemoteAccessResult(roots, reports, errors);
    }

    public static IReadOnlyList<RemoteTargetSpec> LoadTargets(
        IEnumerable<string> directHosts,
        string? hostsFile,
        IReadOnlyList<string> defaultShares)
    {
        var raw = new List<(string Host, IReadOnlyList<string>? Shares)>();
        foreach (string host in directHosts)
            raw.Add((ValidateHost(host), null));

        if (!string.IsNullOrWhiteSpace(hostsFile))
        {
            string path = Path.GetFullPath(hostsFile);
            foreach (string sourceLine in File.ReadLines(path))
            {
                string line = sourceLine.Trim();
                if (line.Length == 0 || line.StartsWith('#'))
                    continue;

                string[] parts = line.Split('|', 2, StringSplitOptions.TrimEntries);
                string host = ValidateHost(parts[0]);
                IReadOnlyList<string>? shares = null;
                if (parts.Length == 2 && !string.IsNullOrWhiteSpace(parts[1]))
                {
                    shares = parts[1]
                        .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .Select(ValidateShare)
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToArray();
                }
                raw.Add((host, shares));
            }
        }

        string[] normalizedDefaults = defaultShares
            .Select(ValidateShare)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return raw
            .GroupBy(x => x.Host, StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                string[] explicitShares = group
                    .Where(x => x.Shares is not null)
                    .SelectMany(x => x.Shares!)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                IReadOnlyList<string> shares = explicitShares.Length > 0 ? explicitShares : normalizedDefaults;
                if (shares.Count == 0)
                    throw new ArgumentException($"Remote host '{group.Key}' has no explicit share. Add --remote-share <name> or specify HOST|Share in the hosts file.");
                return new RemoteTargetSpec(group.Key, shares);
            })
            .ToArray();
    }

    public static string ReadPasswordInteractively(string prompt = "Password")
    {
        if (Console.IsInputRedirected)
            throw new InvalidOperationException("Interactive password entry is unavailable when stdin is redirected. Use the corresponding --*-password-stdin option.");

        Console.Write(prompt + ": ");
        var chars = new List<char>();
        while (true)
        {
            ConsoleKeyInfo key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                break;
            }
            if (key.Key == ConsoleKey.Backspace)
            {
                if (chars.Count > 0)
                    chars.RemoveAt(chars.Count - 1);
                continue;
            }
            if (!char.IsControl(key.KeyChar))
                chars.Add(key.KeyChar);
        }
        return new string(chars.ToArray());
    }

    public static string ReadPasswordFromStdin()
    {
        string? password = Console.In.ReadLine();
        if (password is null)
            throw new InvalidOperationException("No password was received on stdin.");
        return password.TrimEnd('\r', '\n');
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (!OperatingSystem.IsWindows()) return;

        for (int i = _connectionsCreated.Count - 1; i >= 0; i--)
        {
            try { WNetCancelConnection2(_connectionsCreated[i], 0, false); }
            catch { }
        }
        _connectionsCreated.Clear();
    }

    private static string ValidateHost(string input)
    {
        string host = input.Trim();
        if (host.StartsWith(@"\\", StringComparison.Ordinal))
            host = host.TrimStart('\\').Split('\\', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(host))
            throw new ArgumentException("Remote host cannot be empty.");
        if (host.IndexOfAny(new[] { '*', '?', '/', '\\', ',', ';' }) >= 0 || host.Contains("..", StringComparison.Ordinal))
            throw new ArgumentException($"Remote host '{input}' is not an explicit hostname/IP. Wildcards, CIDR/ranges, paths and lists are not accepted.");
        if (host.Contains(':'))
            throw new ArgumentException($"Remote host '{input}' contains ':'. Use a Windows hostname or IPv4 address; IPv6 UNC literals must be supplied in Windows ipv6-literal form.");
        return host;
    }

    private static string ValidateShare(string input)
    {
        string share = input.Trim();
        if (string.IsNullOrWhiteSpace(share))
            throw new ArgumentException("Remote share cannot be empty.");
        if (share is "." or ".." || share.IndexOfAny(new[] { '\\', '/', '*', '?', ':', '|', '"', '<', '>' }) >= 0)
            throw new ArgumentException($"Remote share '{input}' must be one explicit SMB share name, for example C$ or Data.");
        return share;
    }

    private static int ConnectShare(string remoteRoot, string username, string password)
    {
        var resource = new NETRESOURCE
        {
            dwType = ResourceTypeDisk,
            lpRemoteName = remoteRoot
        };
        return WNetAddConnection2(ref resource, password, username, 0);
    }

    private static RemoteTargetReport BuildUnsupportedReport(RemoteTargetSpec target)
    {
        ResolveHost(target.Host, out string hostName, out var v4, out var v6);
        return new RemoteTargetReport(
            target.Host,
            hostName,
            v4,
            v6,
            "ExplicitCredential",
            RemoteAuthenticationStatus.UnsupportedPlatform,
            target.Shares.Select(s => new RemoteShareAccessReport(s, $@"\\{target.Host}\{s}", false, null, "Credentialed SMB connection is supported only on Windows in this build.")).ToArray());
    }

    private static void ResolveHost(string host, out string hostName, out IReadOnlyList<string> v4, out IReadOnlyList<string> v6)
    {
        hostName = host;
        var ipv4 = new List<string>();
        var ipv6 = new List<string>();
        try
        {
            IPHostEntry entry = Dns.GetHostEntry(host);
            if (!string.IsNullOrWhiteSpace(entry.HostName))
                hostName = entry.HostName;
            foreach (IPAddress address in entry.AddressList)
            {
                if (address.AddressFamily == AddressFamily.InterNetwork) ipv4.Add(address.ToString());
                else if (address.AddressFamily == AddressFamily.InterNetworkV6) ipv6.Add(address.ToString());
            }
        }
        catch
        {
            if (IPAddress.TryParse(host, out IPAddress? address))
            {
                if (address.AddressFamily == AddressFamily.InterNetwork) ipv4.Add(address.ToString());
                else if (address.AddressFamily == AddressFamily.InterNetworkV6) ipv6.Add(address.ToString());
            }
        }
        v4 = ipv4.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        v6 = ipv6.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NETRESOURCE
    {
        public int dwScope;
        public int dwType;
        public int dwDisplayType;
        public int dwUsage;
        public string? lpLocalName;
        public string? lpRemoteName;
        public string? lpComment;
        public string? lpProvider;
    }

    [DllImport("mpr.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int WNetAddConnection2(ref NETRESOURCE lpNetResource, string? lpPassword, string? lpUserName, int dwFlags);

    [DllImport("mpr.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int WNetCancelConnection2(string lpName, int dwFlags, bool fForce);
}

public sealed record RemoteAccessResult(
    IReadOnlyList<string> Roots,
    IReadOnlyList<RemoteTargetReport> Reports,
    IReadOnlyList<string> Errors);
