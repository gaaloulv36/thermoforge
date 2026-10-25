namespace ThermoForge.Core.Processes;

/// <summary>
/// Watches resource use over time and flags the classic crypto-miner pattern: a process that
/// keeps the CPU or GPU busy while nobody is using the PC. Not thread-safe; call
/// <see cref="Observe"/> from the polling thread only.
/// </summary>
public sealed class BehaviorTracker
{
    /// <summary>Share of the whole CPU (all cores) or of the busiest GPU engine that counts as heavy.</summary>
    public const double HeavyCpuPercent = 25;
    public const double HeavyGpuPercent = 40;

    /// <summary>How long the user must be away, and the load must last, before it is reported.</summary>
    public static readonly TimeSpan IdleThreshold = TimeSpan.FromMinutes(2);
    public static readonly TimeSpan SustainedFor = TimeSpan.FromMinutes(2);

    /// <summary>A short dip below the threshold (one missed poll) doesn't reset the streak.</summary>
    private static readonly TimeSpan GracePeriod = TimeSpan.FromSeconds(10);

    private readonly Dictionary<ProcessKey, Streak> _streaks = new();

    /// <summary>Call once per poll with every live process; returns the behaviour findings per process.</summary>
    public IReadOnlyDictionary<ProcessKey, ProcessFinding> Observe(
        IEnumerable<Usage> processes, DateTime nowUtc, TimeSpan userIdle)
    {
        var findings = new Dictionary<ProcessKey, ProcessFinding>();
        var alive = new HashSet<ProcessKey>();
        var userAway = userIdle >= IdleThreshold;

        foreach (var usage in processes)
        {
            alive.Add(usage.Key);
            var heavy = usage.CpuPercent >= HeavyCpuPercent || usage.GpuPercent >= HeavyGpuPercent;

            if (!userAway || !heavy)
            {
                // Keep a recent streak through a brief dip, but forget it once the user is back.
                if (!userAway || !_streaks.TryGetValue(usage.Key, out var s) || nowUtc - s.LastHeavyUtc > GracePeriod)
                    _streaks.Remove(usage.Key);
                continue;
            }

            if (!_streaks.TryGetValue(usage.Key, out var streak))
                streak = new Streak(nowUtc, nowUtc, 0, 0);
            streak = streak with
            {
                LastHeavyUtc = nowUtc,
                PeakCpu = Math.Max(streak.PeakCpu, usage.CpuPercent),
                PeakGpu = Math.Max(streak.PeakGpu, usage.GpuPercent),
            };
            _streaks[usage.Key] = streak;

            if (nowUtc - streak.StartUtc >= SustainedFor)
                findings[usage.Key] = Describe(streak, nowUtc, usage.Signature);
        }

        foreach (var gone in _streaks.Keys.Where(k => !alive.Contains(k)).ToList())
            _streaks.Remove(gone);

        return findings;
    }

    private static ProcessFinding Describe(Streak streak, DateTime nowUtc, SignatureStatus? signature)
    {
        var minutes = Math.Max(1, (int)(nowUtc - streak.StartUtc).TotalMinutes);
        var what = streak.PeakGpu >= HeavyGpuPercent
            ? $"the graphics card (up to {streak.PeakGpu:F0} %)"
            : $"the CPU (up to {streak.PeakCpu:F0} %)";
        var detail = $"Kept {what} busy for {minutes} min while nobody was using the PC. ";

        return signature switch
        {
            SignatureStatus.Signed => new ProcessFinding(FindingSeverity.Low, "Busy while you're away",
                detail + "It is signed, so this is probably scheduled work (updates, indexing, backups, scans)."),
            SignatureStatus.Unsigned or SignatureStatus.Invalid => new ProcessFinding(FindingSeverity.High, "Possible crypto-miner",
                detail + "Unsigned programs that only work hard when you're away are the typical pattern of hidden crypto-miners."),
            _ => new ProcessFinding(FindingSeverity.Medium, "Heavy load while you're away",
                detail + "Its publisher could not be checked. Run as administrator to verify it."),
        };
    }

    public readonly record struct ProcessKey(int Pid, DateTime? StartTime);

    public sealed record Usage(ProcessKey Key, double CpuPercent, double GpuPercent, SignatureStatus? Signature);

    private sealed record Streak(DateTime StartUtc, DateTime LastHeavyUtc, double PeakCpu, double PeakGpu);
}
