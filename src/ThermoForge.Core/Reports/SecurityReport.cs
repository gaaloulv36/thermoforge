using System.Text.Json;
using System.Text.Json.Serialization;
using ThermoForge.Core.Alerts;
using ThermoForge.Core.Models;
using ThermoForge.Core.Network;
using ThermoForge.Core.Platform;
using ThermoForge.Core.Processes;
using ThermoForge.Core.Reputation;
using ThermoForge.Core.Services;
using ThermoForge.Core.Startup;

namespace ThermoForge.Core.Reports;

/// <summary>Something flagged, in a form that reads the same for processes, startup entries and connections.</summary>
/// <param name="Context">What it is or where it lives: "PID 1234", "Scheduled task", "Out to 1.2.3.4:443".</param>
public sealed record ReportItem(
    string Name,
    string Context,
    string? Path,
    string? Publisher,
    int Risk,
    FindingSeverity Severity,
    bool IsTrusted,
    IReadOnlyList<ProcessFinding> Findings);

public sealed record ReportTemperature(string Device, string Sensor, double Celsius, TemperatureStatus Status);

/// <param name="Hosts">A few of the servers it talks to (host names where known).</param>
public sealed record ReportTraffic(string Program, int Connections, IReadOnlyList<string> Hosts);

/// <param name="Verdict">Worst problem found, used for the headline.</param>
/// <param name="Highlights">Plain-language reasons for the verdict, most serious first.</param>
public sealed record SecurityReport(
    DateTime GeneratedAt,
    string ComputerName,
    string UserName,
    string WindowsVersion,
    bool IsAdministrator,
    FindingSeverity Verdict,
    IReadOnlyList<string> Highlights,
    int ProcessCount,
    int StartupCount,
    int ConnectionCount,
    IReadOnlyList<ReportTemperature> Temperatures,
    IReadOnlyList<ReportItem> Processes,
    IReadOnlyList<ReportItem> StartupEntries,
    IReadOnlyList<ReportItem> Connections,
    IReadOnlyList<ReportTraffic> InternetTraffic,
    DefenderStatus? Defender,
    IReadOnlyList<DefenderDetection> DefenderDetections,
    IReadOnlyList<FileReputation> FileChecks,
    IReadOnlyList<Alert> Alerts)
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public string ToJson() => JsonSerializer.Serialize(this, JsonOptions);
}

/// <summary>Everything the app currently knows, gathered for a report.</summary>
public sealed record ReportInputs(
    ProcessSnapshot? Processes,
    StartupScan? Startup,
    SensorSnapshot? Sensors,
    DefenderStatus? Defender,
    IReadOnlyList<DefenderDetection> DefenderDetections,
    IReadOnlyList<FileReputation> FileChecks,
    IReadOnlyList<Alert> Alerts);

public static class ReportBuilder
{
    /// <summary>Defender detections this recent are mentioned in the verdict.</summary>
    public static readonly TimeSpan RecentDetection = TimeSpan.FromDays(30);

    public static SecurityReport Build(ReportInputs inputs, DateTime now, TemperatureThresholds thresholds)
    {
        var processes = (inputs.Processes?.Processes ?? [])
            .Where(p => p.Findings.Count > 0 && (p.Severity > FindingSeverity.None || p.IsTrusted))
            .OrderByDescending(p => p.Risk)
            .Select(p => new ReportItem(p.Process.Name, $"PID {p.Process.Pid}", p.Process.Path, Publisher(p.File),
                p.Risk, p.Severity, p.IsTrusted, p.Findings))
            .ToList();

        var startup = (inputs.Startup?.Entries ?? [])
            .Where(e => e.Severity > FindingSeverity.None || e.IsNew)
            .OrderByDescending(e => e.Risk)
            .Select(e => new ReportItem(e.Raw.Name, AlertEngine.Describe(e.Raw.Source) + (e.IsNew ? " (new)" : ""),
                e.ImagePath ?? e.Raw.Command, Publisher(e.File), e.Risk, e.Severity, e.IsTrusted, e.Findings))
            .ToList();

        var connections = inputs.Processes?.Connections ?? [];
        var trustedPids = (inputs.Processes?.Processes ?? []).Where(p => p.IsTrusted).Select(p => p.Process.Pid).ToHashSet();
        var flaggedConnections = connections
            .Where(c => c.Findings.Count > 0)
            .Select(c =>
            {
                var trusted = trustedPids.Contains(c.Raw.Pid);
                var risk = trusted ? 0 : RiskScore.From(c.Findings);
                return new ReportItem(c.ProcessName, Describe(c), c.ProcessPath, null, risk, RiskScore.Level(risk), trusted, c.Findings);
            })
            .OrderByDescending(c => c.Risk)
            .ToList();

        var traffic = connections
            .Where(c => c.Scope == RemoteScope.Internet)
            .GroupBy(c => c.ProcessName, StringComparer.OrdinalIgnoreCase)
            .Select(g => new ReportTraffic(g.Key, g.Count(),
                g.Select(c => c.HostName ?? c.Raw.Remote!.Address.ToString()).Distinct().Take(5).ToList()))
            .OrderByDescending(t => t.Connections)
            .ToList();

        var temperatures = new List<ReportTemperature>();
        if (inputs.Sensors is { } sensors)
        {
            var summary = SensorSummary.From(sensors.Readings);
            foreach (var reading in new[] { summary.CpuTemperature, summary.GpuTemperature, summary.StorageTemperature }.OfType<SensorReading>())
                temperatures.Add(new ReportTemperature(reading.Hardware, reading.Name, reading.Value, thresholds.Evaluate(reading)));
        }

        var highlights = new List<(FindingSeverity Severity, string Text)>();
        foreach (var item in processes.Concat(startup).Concat(flaggedConnections).Where(i => i.Severity >= FindingSeverity.Medium))
            highlights.Add((item.Severity, $"{item.Severity} risk: {item.Name} ({item.Context}) – {item.Findings.MaxBy(f => f.Severity)!.Title}"));

        if (inputs.Defender?.Problem(now) is { } problem)
            highlights.Add((inputs.Defender.AntivirusEnabled && inputs.Defender.RealTimeProtection ? FindingSeverity.Medium : FindingSeverity.High,
                "Microsoft Defender: " + problem));
        foreach (var detection in inputs.DefenderDetections.Where(d => now - d.Time < RecentDetection))
        {
            highlights.Add((detection.IsUnresolved ? FindingSeverity.High : FindingSeverity.Low,
                $"Defender detected {detection.Threat} on {detection.Time:d} ({detection.Status})"));
        }
        foreach (var hot in temperatures.Where(t => t.Status == TemperatureStatus.Hot))
            highlights.Add((FindingSeverity.Medium, $"{hot.Device} is running hot: {hot.Celsius:F0} °C"));

        var verdict = highlights.Count == 0 ? FindingSeverity.None : highlights.Max(h => h.Severity);
        return new SecurityReport(
            now,
            Environment.MachineName,
            Environment.UserName,
            Environment.OSVersion.VersionString,
            SystemEnvironment.IsAdministrator(),
            verdict,
            highlights.OrderByDescending(h => h.Severity).Select(h => h.Text).Distinct().ToList(),
            inputs.Processes?.Processes.Count ?? 0,
            inputs.Startup?.Entries.Count ?? 0,
            connections.Count,
            temperatures,
            processes,
            startup,
            flaggedConnections,
            traffic,
            inputs.Defender,
            inputs.DefenderDetections,
            inputs.FileChecks.OrderByDescending(f => f.VirusTotal?.Malicious ?? 0).ToList(),
            inputs.Alerts);
    }

    private static string Describe(NetConnection c) => c.Direction switch
    {
        ConnectionDirection.Listening => $"Listening on {c.Raw.Local}",
        ConnectionDirection.Incoming => $"In from {c.Raw.Remote}",
        _ => $"Out to {c.HostName ?? c.Raw.Remote?.Address.ToString()}:{c.Raw.Remote?.Port}",
    };

    private static string? Publisher(FileMetadata? file) => file?.Signature.Status switch
    {
        SignatureStatus.Signed => file.Signature.Signer ?? file.Company,
        SignatureStatus.Unsigned => "Unsigned" + (file.Company is { } company ? $" ({company})" : ""),
        SignatureStatus.Invalid => "Invalid signature",
        _ => null,
    };
}
