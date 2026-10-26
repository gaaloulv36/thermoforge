using System.Net;

namespace ThermoForge.Core.Network;

/// <summary>
/// Spots programs that open a new connection to the same address at a steady rhythm. Only
/// connections that live through at least one poll are seen, so this is best-effort: very
/// short check-ins between two polls go unnoticed. Not thread-safe.
/// </summary>
public sealed class BeaconDetector
{
    /// <summary>Connections needed before a rhythm counts (that is, one fewer gaps).</summary>
    public const int MinConnections = 6;

    /// <summary>Faster than this is ordinary chatty traffic, not a check-in.</summary>
    public static readonly TimeSpan MinInterval = TimeSpan.FromSeconds(10);

    public static readonly TimeSpan MaxInterval = TimeSpan.FromMinutes(30);

    /// <summary>Polls are a few seconds apart, so a perfect timer still looks this uneven.</summary>
    private static readonly TimeSpan Jitter = TimeSpan.FromSeconds(4);

    private const int Window = 8;

    private readonly Dictionary<Key, List<DateTime>> _seen = new();

    /// <param name="Started">With the PID, tells a restarted process from the old one.</param>
    public readonly record struct Key(int Pid, DateTime? Started, IPAddress Remote);

    /// <summary>Records that a new connection to <paramref name="key"/>'s address appeared.</summary>
    public void Record(Key key, DateTime nowUtc)
    {
        if (!_seen.TryGetValue(key, out var times))
            _seen[key] = times = [];
        if (times.Count > 0 && times[^1] == nowUtc)
            return; // Several parallel connections in one poll are one check-in.

        times.Add(nowUtc);
        if (times.Count > Window)
            times.RemoveAt(0);
    }

    /// <summary>The steady interval between connections, or null when there is no rhythm.</summary>
    public TimeSpan? Interval(Key key)
    {
        if (!_seen.TryGetValue(key, out var times) || times.Count < MinConnections)
            return null;

        var gaps = times.Zip(times.Skip(1), (a, b) => b - a).Order().ToList();
        var median = gaps[gaps.Count / 2];
        if (median < MinInterval || median > MaxInterval)
            return null;

        var tolerance = TimeSpan.FromTicks(Math.Max(median.Ticks / 5, Jitter.Ticks));
        return gaps.All(g => (g - median).Duration() <= tolerance) ? median : null;
    }

    /// <summary>Forgets addresses not contacted for a long time, so memory stays bounded.</summary>
    public void Prune(DateTime nowUtc)
    {
        foreach (var key in _seen.Where(s => nowUtc - s.Value[^1] > 2 * MaxInterval).Select(s => s.Key).ToList())
            _seen.Remove(key);
    }
}
