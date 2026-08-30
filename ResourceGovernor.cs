using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SmartBackupDiscovery;

public sealed class ResourceGovernor
{
    private readonly ResourcePolicy _policy;
    private readonly TokenBucket? _globalNetwork;
    private readonly Dictionary<string, TokenBucket> _perHost = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _sync = new();
    private CpuSample? _lastCpu;
    private DateTime _lastCpuSampleUtc;
    private double? _lastCpuPercent;
    private int _adaptiveDelayMs;

    public ResourceGovernor(ResourcePolicy policy)
    {
        _policy = policy;
        if (policy.GlobalNetworkMbps > 0)
            _globalNetwork = new TokenBucket(policy.GlobalNetworkMbps);
    }

    public int IoBufferBytes => Math.Clamp(_policy.IoBufferKiB, 32, 4096) * 1024;
    public int AdaptiveDelayMilliseconds => Volatile.Read(ref _adaptiveDelayMs);

    public void BeforeWork(bool remote)
    {
        UpdateCpuAndThrottle();
        int delay = AdaptiveDelayMilliseconds;
        if (remote && delay > 0)
            Thread.Sleep(delay);
        else if (!remote && delay > 2)
            Thread.Sleep(Math.Max(1, delay / 4));
    }

    public void AccountNetworkBytes(int bytes, string? host)
    {
        if (bytes <= 0)
            return;
        _globalNetwork?.Consume(bytes);
        if (_policy.PerHostNetworkMbps <= 0 || string.IsNullOrWhiteSpace(host))
            return;

        TokenBucket bucket;
        lock (_sync)
        {
            if (!_perHost.TryGetValue(host, out bucket!))
            {
                bucket = new TokenBucket(_policy.PerHostNetworkMbps);
                _perHost[host] = bucket;
            }
        }
        bucket.Consume(bytes);
    }

    private void UpdateCpuAndThrottle()
    {
        if (_policy.MaxCpuPercent >= 100 || _policy.MaxCpuPercent <= 0)
            return;
        if ((DateTime.UtcNow - _lastCpuSampleUtc).TotalMilliseconds < 250)
            return;

        var sample = TrySampleCpu();
        _lastCpuSampleUtc = DateTime.UtcNow;
        if (sample is null)
            return;

        if (_lastCpu is { } previous && sample.Value.Total >= previous.Total && sample.Value.Idle >= previous.Idle)
        {
            ulong totalDelta = sample.Value.Total - previous.Total;
            ulong idleDelta = sample.Value.Idle - previous.Idle;
            if (totalDelta > 0 && idleDelta <= totalDelta)
            {
                double cpu = 100.0 * (totalDelta - idleDelta) / totalDelta;
                _lastCpuPercent = cpu;
                int current = _adaptiveDelayMs;
                if (cpu >= _policy.MaxCpuPercent)
                {
                    current = Math.Min(_policy.MaxAdaptiveDelayMilliseconds, Math.Max(2, current == 0 ? 4 : current * 2));
                    Thread.Sleep(Math.Min(250, Math.Max(10, current)));
                }
                else if (cpu <= Math.Max(5, _policy.MaxCpuPercent - 18))
                {
                    current = Math.Max(0, current - Math.Max(1, current / 3));
                }
                Interlocked.Exchange(ref _adaptiveDelayMs, current);
            }
        }
        _lastCpu = sample;
    }

    private static CpuSample? TrySampleCpu()
    {
        if (OperatingSystem.IsWindows())
        {
            if (GetSystemTimes(out var idle, out var kernel, out var user))
            {
                ulong idleTicks = ToUInt64(idle);
                ulong kernelTicks = ToUInt64(kernel);
                ulong userTicks = ToUInt64(user);
                return new CpuSample(idleTicks, kernelTicks + userTicks);
            }
            return null;
        }

        if (OperatingSystem.IsLinux())
        {
            try
            {
                string? first = File.ReadLines("/proc/stat").FirstOrDefault();
                if (string.IsNullOrWhiteSpace(first) || !first.StartsWith("cpu ", StringComparison.Ordinal)) return null;
                string[] fields = first.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (fields.Length < 5) return null;
                ulong[] ticks = fields.Skip(1).Select(x => ulong.TryParse(x, out ulong value) ? value : 0UL).ToArray();
                ulong total = 0;
                foreach (ulong tick in ticks) total = total > ulong.MaxValue - tick ? ulong.MaxValue : total + tick;
                ulong idle = ticks.Length > 3 ? ticks[3] : 0;
                if (ticks.Length > 4) idle = idle > ulong.MaxValue - ticks[4] ? ulong.MaxValue : idle + ticks[4];
                return new CpuSample(idle, total);
            }
            catch { return null; }
        }

        // Portable fallback: throttle on this process rather than host CPU when no native host metric exists.
        try
        {
            using var process = Process.GetCurrentProcess();
            ulong wall = (ulong)Environment.TickCount64;
            ulong busy = (ulong)Math.Max(0, process.TotalProcessorTime.TotalMilliseconds);
            ulong total = Math.Max(wall, busy);
            ulong idle = total > busy ? total - busy : 0;
            return new CpuSample(idle, total);
        }
        catch { return null; }
    }

    private static ulong ToUInt64(FILETIME value) => ((ulong)value.dwHighDateTime << 32) | value.dwLowDateTime;

    private readonly record struct CpuSample(ulong Idle, ulong Total);

    [StructLayout(LayoutKind.Sequential)]
    private struct FILETIME
    {
        public uint dwLowDateTime;
        public uint dwHighDateTime;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetSystemTimes(out FILETIME idleTime, out FILETIME kernelTime, out FILETIME userTime);

    private sealed class TokenBucket
    {
        private readonly double _bytesPerSecond;
        private readonly double _capacity;
        private double _tokens;
        private long _lastTimestamp;
        private readonly object _gate = new();

        public TokenBucket(double mbps)
        {
            _bytesPerSecond = mbps * 1_000_000.0 / 8.0;
            _capacity = Math.Max(64 * 1024, _bytesPerSecond * 0.5);
            _tokens = _capacity;
            _lastTimestamp = Stopwatch.GetTimestamp();
        }

        public void Consume(int bytes)
        {
            if (bytes <= 0 || _bytesPerSecond <= 0)
                return;

            int remaining = bytes;
            while (remaining > 0)
            {
                int request = Math.Min(remaining, Math.Max(1, (int)Math.Floor(_capacity)));
                while (true)
                {
                    int sleepMs;
                    lock (_gate)
                    {
                        long now = Stopwatch.GetTimestamp();
                        double elapsed = (now - _lastTimestamp) / (double)Stopwatch.Frequency;
                        _lastTimestamp = now;
                        _tokens = Math.Min(_capacity, _tokens + elapsed * _bytesPerSecond);
                        if (_tokens >= request)
                        {
                            _tokens -= request;
                            remaining -= request;
                            break;
                        }

                        double missing = request - _tokens;
                        sleepMs = Math.Clamp((int)Math.Ceiling(missing / _bytesPerSecond * 1000.0), 1, 500);
                    }
                    Thread.Sleep(sleepMs);
                }
            }
        }
    }
}
