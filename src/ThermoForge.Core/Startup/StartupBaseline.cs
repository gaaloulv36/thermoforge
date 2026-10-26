using System.Text.Json;

namespace ThermoForge.Core.Startup;

/// <summary>
/// Remembers when each auto-start entry was first seen, so entries added after ThermoForge
/// started watching can be pointed out. Saved between runs; not thread-safe.
/// </summary>
/// <remarks>
/// Each "context" (a source, read with or without admin rights) gets its own baseline. Running
/// as administrator for the first time reveals tasks and subscriptions Windows hid before;
/// those were there all along, so they must not show up as new.
/// </remarks>
public sealed class StartupBaseline
{
    /// <summary>How long an entry stays marked as new.</summary>
    public static readonly TimeSpan NewFor = TimeSpan.FromDays(7);

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly string? _filePath;
    private readonly State _state;

    /// <param name="filePath">Where to persist it; null keeps it in memory (tests).</param>
    public StartupBaseline(string? filePath)
    {
        _filePath = filePath;
        _state = Load(filePath);
    }

    public static string DefaultPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ThermoForge", "startup-baseline.json");

    /// <summary>
    /// Records the entries seen in a scan and returns, per id, whether it is new. A context's
    /// first scan only establishes its baseline: nothing in it counts as new.
    /// </summary>
    /// <param name="completeContexts">Contexts read without errors; only those forget vanished entries.</param>
    public IReadOnlyDictionary<string, Observation> Observe(
        IEnumerable<(string Id, string Context)> entries, IReadOnlySet<string> completeContexts, DateTime nowUtc)
    {
        var result = new Dictionary<string, Observation>();
        var seenByContext = new Dictionary<string, HashSet<string>>();

        // A source read in full starts its baseline even when empty, so the first entry that
        // ever appears in it (say, a WMI subscription) is reported as new.
        foreach (var context in completeContexts)
            _state.ContextsCreatedUtc.TryAdd(context, nowUtc);

        foreach (var (id, context) in entries)
        {
            if (!_state.ContextsCreatedUtc.TryGetValue(context, out var created))
                _state.ContextsCreatedUtc[context] = created = nowUtc;
            if (!_state.FirstSeen.TryGetValue(id, out var first))
                _state.FirstSeen[id] = first = nowUtc;

            (seenByContext.TryGetValue(context, out var ids) ? ids : seenByContext[context] = []).Add(id);
            result[id] = new Observation(first, first > created && nowUtc - first < NewFor);
        }

        // Forget entries that are gone, so one that comes back later is reported again. Only for
        // contexts read in full: an unreadable source must not make everything "new" next time.
        foreach (var context in completeContexts)
        {
            var current = seenByContext.GetValueOrDefault(context) ?? [];
            if (!_state.Members.TryGetValue(context, out var previous))
                previous = [];
            foreach (var gone in previous.Where(id => !current.Contains(id)))
                _state.FirstSeen.Remove(gone);
            _state.Members[context] = current;
        }
        foreach (var (context, ids) in seenByContext.Where(c => !completeContexts.Contains(c.Key)))
            _state.Members[context] = [.. _state.Members.GetValueOrDefault(context) ?? [], .. ids];

        Save();
        return result;
    }

    private void Save()
    {
        if (_filePath is null)
            return;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_filePath)!);
            File.WriteAllText(_filePath, JsonSerializer.Serialize(_state, JsonOptions));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Losing the baseline only means entries aren't marked new; monitoring goes on.
        }
    }

    private static State Load(string? filePath)
    {
        try
        {
            return filePath is not null && File.Exists(filePath)
                ? JsonSerializer.Deserialize<State>(File.ReadAllText(filePath)) ?? new()
                : new();
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            return new();
        }
    }

    public readonly record struct Observation(DateTime FirstSeenUtc, bool IsNew);

    private sealed class State
    {
        public Dictionary<string, DateTime> ContextsCreatedUtc { get; set; } = new();
        public Dictionary<string, DateTime> FirstSeen { get; set; } = new();
        public Dictionary<string, HashSet<string>> Members { get; set; } = new();
    }
}
