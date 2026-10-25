using System.Management;

namespace ThermoForge.Core.Processes;

/// <summary>
/// Takes process snapshots from WMI (one query gives paths, command lines, parents and CPU
/// times, without opening each process), derives CPU % from the change since the previous
/// snapshot, and runs every process through <see cref="ProcessAnalyzer"/>.
/// Call <see cref="Poll"/> from a single thread.
/// </summary>
public sealed class ProcessMonitor : IDisposable
{
    private const string Query =
        "SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate, " +
        "KernelModeTime, UserModeTime, WorkingSetSize FROM Win32_Process";

    private readonly ManagementObjectSearcher _searcher = new("root\\CIMV2", Query);
    private readonly FileMetadataCache _files = new();
    private readonly ProcessAnalyzer _analyzer;
    private Dictionary<ProcessKey, ulong> _previousCpuTime = new();
    private DateTime _previousPollUtc;

    public ProcessMonitor(ProcessAnalyzer analyzer)
    {
        _analyzer = analyzer;
    }

    public ProcessSnapshot Poll()
    {
        var samples = ReadProcesses();
        var nowUtc = DateTime.UtcNow;
        var elapsedTicks = _previousPollUtc == default ? 0 : (nowUtc - _previousPollUtc).Ticks;
        var byPid = samples.ToDictionary(s => s.Process.Pid, s => s.Process);

        var cpuTimes = new Dictionary<ProcessKey, ulong>(samples.Count);
        var processes = new List<ProcessInfo>(samples.Count);

        foreach (var sample in samples)
        {
            var process = sample.Process;
            var key = new ProcessKey(process.Pid, process.StartTime);
            cpuTimes[key] = sample.CpuTime;

            var parent = FindParent(process, byPid);
            var file = process.Path is null ? null : _files.Get(process.Path);

            processes.Add(new ProcessInfo(
                process,
                parent,
                CpuPercent(key, sample.CpuTime, elapsedTicks),
                sample.WorkingSetBytes,
                file,
                // Don't report ourselves: a dev build is unsigned and may well run from a temp folder.
                process.Pid == Environment.ProcessId ? [] : _analyzer.Analyze(process, parent, file?.Signature)));
        }

        _previousCpuTime = cpuTimes;
        _previousPollUtc = nowUtc;
        return new ProcessSnapshot(DateTime.Now, processes);
    }

    public void Dispose() => _searcher.Dispose();

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
                        obj["ExecutablePath"] as string,
                        obj["CommandLine"] as string,
                        string.IsNullOrEmpty(created) ? null : ManagementDateTimeConverter.ToDateTime(created)),
                    Convert.ToUInt64(obj["KernelModeTime"]) + Convert.ToUInt64(obj["UserModeTime"]),
                    Convert.ToInt64(obj["WorkingSetSize"])));
            }
        }
        return samples;
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
}
