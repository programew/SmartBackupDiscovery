using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace SmartBackupDiscovery;

public sealed class SystemNetworkHostProbe : INetworkHostProbe
{
    public async Task<NetworkProbeObservation> ProbeAsync(
        IPAddress address,
        NetworkDiscoveryPolicy policy,
        CancellationToken cancellationToken)
    {
        Task<(bool Reachable, long? Roundtrip)> icmpTask = policy.UseIcmp
            ? ProbeIcmpAsync(address, policy.ProbeTimeoutMilliseconds, cancellationToken)
            : Task.FromResult((false, (long?)null));

        Task<int?>[] tcpTasks = policy.TcpPorts
            .Select(port => ProbeTcpAsync(address, port, policy.ProbeTimeoutMilliseconds, cancellationToken))
            .ToArray();

        (bool icmpReachable, long? roundtrip) = await icmpTask.ConfigureAwait(false);
        int?[] tcpResults = await Task.WhenAll(tcpTasks).ConfigureAwait(false);
        int[] openPorts = tcpResults.Where(x => x.HasValue).Select(x => x!.Value).OrderBy(x => x).ToArray();

        string? hostName = null;
        if (policy.ResolveDns && (icmpReachable || openPorts.Length > 0))
            hostName = await TryResolveHostNameAsync(address, policy.ProbeTimeoutMilliseconds, cancellationToken).ConfigureAwait(false);

        return new NetworkProbeObservation(icmpReachable, roundtrip, openPorts, hostName);
    }

    private static async Task<(bool Reachable, long? Roundtrip)> ProbeIcmpAsync(
        IPAddress address,
        int timeoutMilliseconds,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            using var ping = new Ping();
            PingReply reply = await ping.SendPingAsync(address, timeoutMilliseconds).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            return reply.Status == IPStatus.Success
                ? (true, reply.RoundtripTime)
                : (false, null);
        }
        catch (OperationCanceledException) { throw; }
        catch { return (false, null); }
    }

    private static async Task<int?> ProbeTcpAsync(
        IPAddress address,
        int port,
        int timeoutMilliseconds,
        CancellationToken cancellationToken)
    {
        try
        {
            using var client = new TcpClient(address.AddressFamily);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(timeoutMilliseconds);
            await client.ConnectAsync(address, port, timeout.Token).ConfigureAwait(false);
            return client.Connected ? port : null;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return null; }
        catch (OperationCanceledException) { throw; }
        catch { return null; }
    }

    private static async Task<string?> TryResolveHostNameAsync(
        IPAddress address,
        int timeoutMilliseconds,
        CancellationToken cancellationToken)
    {
        try
        {
            IPHostEntry entry = await Dns.GetHostEntryAsync(address)
                .WaitAsync(TimeSpan.FromMilliseconds(timeoutMilliseconds), cancellationToken)
                .ConfigureAwait(false);
            string name = entry.HostName.Trim().TrimEnd('.');
            return string.IsNullOrWhiteSpace(name) || name.Equals(address.ToString(), StringComparison.OrdinalIgnoreCase)
                ? null
                : name;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch { return null; }
    }
}
