using ThermoForge.Core.Models;
using ThermoForge.Core.Processes;
using ThermoForge.Core.Reputation;
using ThermoForge.Core.Services;
using ThermoForge.Core.Startup;

namespace ThermoForge.Core.Alerts;

public enum AlertKind
{
    Process,
    Temperature,
    Startup,

    /// <summary>Antivirus problems: Defender turned off, or a threat it found.</summary>
    Security,

    /// <summary>A newer ThermoForge is available.</summary>
    Update,
}

/// <param name="Pid">The process the alert is about, for "show me" actions.</param>
public sealed record Alert(
    DateTime Time,
    AlertKind Kind,
    FindingSeverity Severity,
    string Title,
    string Message,
    int? Pid = null);

/// <summary>
/// Turns snapshots into alerts, without repeating itself: a process alerts once per risk
/// level it reaches, and a temperature alerts when it stays hot, then not again for a while.
/// Not thread-safe; call from one thread.
/// </summary>
public sealed class AlertEngine
{
    /// <summary>A reading must stay Hot this long, so a brief spike doesn't alert.</summary>
    public static readonly TimeSpan HotFor = TimeSpan.FromSeconds(15);

    /// <summary>Minimum gap between two alerts for the same sensor.</summary>
    public static readonly TimeSpan TemperatureCooldown = TimeSpan.FromMinutes(15);

    private readonly Dictionary<(int Pid, DateTime? Started), FindingSeverity> _alertedLevel = new();
    private readonly Dictionary<string, DateTime> _hotSince = new();
    private readonly Dictionary<string, DateTime> _lastTemperatureAlert = new();
    private readonly HashSet<string> _alertedStartup = new();
    private readonly TemperatureThresholds _thresholds;
    private bool _baselineTaken;
    private bool _startupBaselineTaken;
    private readonly HashSet<string> _knownDetections = new();
    private bool _detectionsBaselineTaken;
    private string? _lastDefenderProblem;

    public AlertEngine(TemperatureThresholds thresholds)
    {
        _thresholds = thresholds;
    }

    /// <summary>Lowest process risk level that raises an alert.</summary>
    public FindingSeverity MinimumProcessSeverity { get; set; } = FindingSeverity.Medium;

    public IReadOnlyList<Alert> Evaluate(ProcessSnapshot snapshot)
    {
        var alerts = new List<Alert>();
        var alive = new HashSet<(int, DateTime?)>();

        foreach (var info in snapshot.Processes)
        {
            var key = (info.Process.Pid, info.Process.StartTime);
            alive.Add(key);

            var level = info.Severity;
            var previous = _alertedLevel.GetValueOrDefault(key);
            if (level <= previous)
                continue;
            _alertedLevel[key] = level;

            // Processes already running at startup were visible in the list the moment the
            // window opened; alert for those only if they get worse later.
            if (_baselineTaken && level >= MinimumProcessSeverity)
                alerts.Add(ForProcess(info, snapshot.Timestamp));
        }

        foreach (var gone in _alertedLevel.Keys.Where(k => !alive.Contains(k)).ToList())
            _alertedLevel.Remove(gone);

        _baselineTaken = true;
        return alerts;
    }

    /// <summary>The processes that were already risky when monitoring started.</summary>
    public static IReadOnlyList<Alert> StartupSummary(ProcessSnapshot snapshot, FindingSeverity minimum)
    {
        var risky = snapshot.Processes.Where(p => p.Severity >= minimum).ToList();
        if (risky.Count == 0)
            return [];
        if (risky.Count == 1)
            return [ForProcess(risky[0], snapshot.Timestamp)];

        var worst = risky.Max(p => p.Severity);
        var names = string.Join(", ", risky.OrderByDescending(p => p.Risk).Take(3).Select(p => p.Process.Name));
        return [new Alert(snapshot.Timestamp, AlertKind.Process, worst,
            $"{risky.Count} risky processes running",
            $"{names}{(risky.Count > 3 ? ", …" : "")}. Open ThermoForge to review them.")];
    }

    public IReadOnlyList<Alert> Evaluate(SensorSnapshot snapshot)
    {
        var alerts = new List<Alert>();
        var summary = SensorSummary.From(snapshot.Readings);
        SensorReading?[] watched = [summary.CpuTemperature, summary.GpuTemperature, summary.StorageTemperature];

        foreach (var reading in watched.OfType<SensorReading>())
        {
            if (_thresholds.Evaluate(reading) != TemperatureStatus.Hot)
            {
                _hotSince.Remove(reading.Id);
                continue;
            }

            var since = _hotSince.TryGetValue(reading.Id, out var start) ? start : _hotSince[reading.Id] = snapshot.Timestamp;
            if (snapshot.Timestamp - since < HotFor)
                continue;
            if (_lastTemperatureAlert.TryGetValue(reading.Id, out var last) && snapshot.Timestamp - last < TemperatureCooldown)
                continue;

            _lastTemperatureAlert[reading.Id] = snapshot.Timestamp;
            var limit = _thresholds.For(reading.Category).Hot;
            alerts.Add(new Alert(snapshot.Timestamp, AlertKind.Temperature, FindingSeverity.High,
                $"{reading.Hardware} is running hot",
                $"{reading.Name} has been at {reading.Value:F0} °C (limit {limit:F0} °C) for over {HotFor.TotalSeconds:F0} seconds. "
                + "Check that the vents are clear and see which process is using it."));
        }

        return alerts;
    }

    /// <summary>
    /// New auto-start entries found after the first scan of this session. Entries ThermoForge
    /// already knew about, or found on the first scan, are shown on the Startup tab instead.
    /// </summary>
    public IReadOnlyList<Alert> Evaluate(StartupScan scan)
    {
        var alerts = new List<Alert>();
        foreach (var entry in scan.Entries.Where(e => e.IsNew))
        {
            if (!_alertedStartup.Add(entry.Raw.Id) || !_startupBaselineTaken)
                continue;

            var severity = entry.Severity == FindingSeverity.None ? FindingSeverity.Low : entry.Severity;
            var top = entry.Findings.MaxBy(f => f.Severity);
            alerts.Add(new Alert(scan.Timestamp, AlertKind.Startup, severity,
                $"New startup entry: {entry.Raw.Name}",
                $"{Describe(entry.Raw.Source)} added: {entry.ImagePath ?? entry.Raw.Command ?? "unknown program"}."
                + (top is null ? "" : $" {top.Title}.")));
        }

        _startupBaselineTaken = true;
        return alerts;
    }

    /// <summary>
    /// Defender switched off (once per problem) and threats it detects while ThermoForge runs.
    /// Its older history is on the Security tab, not alerted again.
    /// </summary>
    public IReadOnlyList<Alert> Evaluate(DefenderStatus? status, IReadOnlyList<DefenderDetection> detections, DateTime now)
    {
        var alerts = new List<Alert>();
        var problem = status?.Problem(now);
        if (problem is not null && problem != _lastDefenderProblem)
        {
            var weakened = status!.AntivirusEnabled && status.RealTimeProtection;
            alerts.Add(new Alert(now, AlertKind.Security, weakened ? FindingSeverity.Medium : FindingSeverity.High,
                weakened ? "Antivirus needs attention" : "Antivirus protection is off",
                problem + " Open Windows Security to fix it."));
        }
        _lastDefenderProblem = problem;

        foreach (var detection in detections.OrderBy(d => d.Time))
        {
            if (!_knownDetections.Add(detection.Id) || !_detectionsBaselineTaken)
                continue;
            var where = detection.Resources.FirstOrDefault() ?? detection.ProcessName ?? "unknown location";
            alerts.Add(new Alert(detection.Time, AlertKind.Security, FindingSeverity.High,
                $"Microsoft Defender found {detection.Threat}",
                $"{detection.Status}: {where}."));
        }
        _detectionsBaselineTaken = true;
        return alerts;
    }

    public static string Describe(StartupSource source) => source switch
    {
        StartupSource.RunKey => "Registry Run key",
        StartupSource.StartupFolder => "Startup folder item",
        StartupSource.ScheduledTask => "Scheduled task",
        StartupSource.Service => "Service",
        StartupSource.Driver => "Driver",
        StartupSource.Winlogon => "Winlogon setting",
        StartupSource.LaunchHijack => "Launch hijack",
        StartupSource.WmiSubscription => "WMI subscription",
        _ => source.ToString(),
    };

    private static Alert ForProcess(ProcessInfo info, DateTime time)
    {
        var top = info.Findings.MaxBy(f => f.Severity)!;
        var more = info.Findings.Count > 1 ? $" (+{info.Findings.Count - 1} more)" : "";
        return new Alert(time, AlertKind.Process, info.Severity,
            $"{info.Severity} risk: {info.Process.Name}",
            $"{top.Title}{more}. Risk score {info.Risk}/100.",
            info.Process.Pid);
    }
}
