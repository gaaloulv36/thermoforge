using System.Management;
using ThermoForge.Core.Platform;

namespace ThermoForge.Core.Processes;

/// <summary>
/// Takes process snapshots from WMI (one query gives paths, command lines, parents and CPU
/// times, without opening each process), derives CPU % from the change since the previous
/// snapshot, and runs every process through <see cref="ProcessAnalyzer"/> and
/// <see cref="BehaviorTracker"/>. Programs in the <see cref="TrustStore"/> keep their findings
/// for display but score zero risk.
/// Call <see cref="Poll"/> from a single thread.
/// </summary>
public sealed class ProcessMonitor : IDisposable
{
    private const string Query =
        "SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate, " +
        "KernelModeTime, UserModeTime, WorkingSetSize FROM Win32_Process";

    private readonly ManagementObjectSearcher _searcher = new("root\\CIMV2", Query);
    private readonly FileMetadataCache _files = new();
    private readonly GpuUsageReader _gpu = new();
    private readonly BehaviorTracker _behavior = new();
    private readonly ProcessAnalyzer _analyzer;
    private readonly TrustStore _trust;
    private readonly Func<TimeSpan> _userIdle;
    private Dictionary<ProcessKey, ulong> _previousCpuTime = new();
    private DateTime _previousPollUtc;

    public ProcessMonitor(ProcessAnalyzer analyzer, TrustStore trust, Func<TimeSpan>? userIdle = null)
    {
        _analyzer = analyzer;
        _trust = trust;
        _userIdle = userIdle ?? SystemEnvironment.UserIdleTime;
    }

    public ProcessSnapshot Poll()
    {
        var samples = ReadProcesses();
        var nowUtc = DateTime.UtcNow;
        var elapsedTicks = _previousPollUtc == default ? 0 : (nowUtc - _previousPollUtc).Ticks;
        var byPid = samples.ToDictionary(s => s.Process.Pid, s => s.Process);

        var gpuByPid = _gpu.Read();
        var cpuTimes = new Dictionary<ProcessKey, ulong>(samples.Count);
        var measured = new List<Measured>(samples.Count);

        foreach (var sample in samples)
        {
            var process = sample.Process;
            var key = new ProcessKey(process.Pid, process.StartTime);
            cpuTimes[key] = sample.CpuTime;
            measured.Add(new Measured(
                sample,
                process.Path is null ? null : _files.Get(process.Path),
                CpuPercent(key, sample.CpuTime, elapsedTicks),
                gpuByPid.GetValueOrDefault(process.Pid)));
        }

        var behavior = _behavior.Observe(
            measured.Select(m => new BehaviorTracker.Usage(
                new(m.Sample.Process.Pid, m.Sample.Process.StartTime), m.Cpu, m.Gpu, m.File?.Signature.Status)),
            nowUtc,
            _userIdle());

        var processes = new List<ProcessInfo>(samples.Count);
        foreach (var m in measured)
        {
            var process = m.Sample.Process;
            var parent = FindParent(process, byPid);

            // Don't report ourselves: a dev build is unsigned and may well run from a temp folder.
            IReadOnlyList<ProcessFinding> findings = process.Pid == Environment.ProcessId
                ? []
                : _analyzer.Analyze(process, parent, m.File?.Signature);
            if (process.Pid != Environment.ProcessId
                && behavior.TryGetValue(new(process.Pid, process.StartTime), out var busy))
                findings = [.. findings, busy];

            processes.Add(new ProcessInfo(
                process,
                parent,
                m.Cpu,
                m.Gpu,
                m.Sample.WorkingSetBytes,
                m.File,
                findings,
                _trust.IsTrusted(process.Path)));
        }

        _previousCpuTime = cpuTimes;
        _previousPollUtc = nowUtc;
        return new ProcessSnapshot(DateTime.Now, processes);
    }

    public void Dispose()
    {
        _searcher.Dispose();
        _gpu.Dispose();
    }

    private List<Sample> ReadProcesses()
    {
        var samples = new List<Sample>();
        using var results = _searcher.Get();
        foreach (var obj in results)
        {
            using (obj)
            {
                var pid = Convert.ToInt32(obj["ProcessId"]);
                if (pid == 0)
                    continue; // "System Idle Process": its CPU time is idle time, not work.

                var created = obj["CreationDate"] as string;
                samples.Add(new Sample(
                    new RawProcess(
                        pid,
                        Convert.ToInt32(obj["ParentProcessId"]),
                        (obj["Name"] as string) ?? $"PID {pid}",
                        CleanPath(obj["ExecutablePath"] as string),
                        obj["CommandLine"] as string,
                        string.IsNullOrEmpty(created) ? null : ManagementDateTimeConverter.ToDateTime(created)),
                    Convert.ToUInt64(obj["KernelModeTime"]) + Convert.ToUInt64(obj["UserModeTime"]),
                    Convert.ToInt64(obj["WorkingSetSize"])));
            }
        }
        return samples;
    }

    /// <summary>
    /// Some processes (e.g. conhost started by apps using pseudo-consoles) report an extended-length
    /// path like <c>\\?\C:\Windows\system32\conhost.exe</c>. Strip the prefix so location checks
    /// and display see the ordinary path.
    /// </summary>
    internal static string? CleanPath(string? path)
    {
        if (path is null)
            return null;
        if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
            return @"\\" + path[8..];
        return path.StartsWith(@"\\?\", StringComparison.Ordinal) ? path[4..] : path;
    }

    /// <summary>
    /// Windows reuses PIDs, so a "parent" that started after the child is an unrelated
    /// process that inherited the dead parent's PID.
    /// </summary>
    private static RawProcess? FindParent(RawProcess process, Dictionary<int, RawProcess> byPid)
    {
        if (process.ParentPid == process.Pid || !byPid.TryGetValue(process.ParentPid, out var parent))
            return null;
        if (parent.StartTime is { } parentStart && process.StartTime is { } childStart && parentStart > childStart)
            return null;
        return parent;
    }

    private double CpuPercent(ProcessKey key, ulong cpuTime, long elapsedTicks)
    {
        if (elapsedTicks <= 0 || !_previousCpuTime.TryGetValue(key, out var previous) || cpuTime < previous)
            return 0;

        // CPU times are in 100 ns units, the same as TimeSpan ticks.
        var percent = (cpuTime - previous) * 100.0 / (elapsedTicks * (double)Environment.ProcessorCount);
        return Math.Clamp(percent, 0, 100);
    }

    private readonly record struct ProcessKey(int Pid, DateTime? StartTime);

    private sealed record Sample(RawProcess Process, ulong CpuTime, long WorkingSetBytes);

    private sealed record Measured(Sample Sample, FileMetadata? File, double Cpu, double Gpu);
}
