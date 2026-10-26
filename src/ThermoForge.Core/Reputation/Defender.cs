using System.Diagnostics;
using System.Management;
using System.Text.RegularExpressions;

namespace ThermoForge.Core.Reputation;

/// <param name="RunningMode">"Normal", or e.g. "Passive Mode" when another antivirus is in charge.</param>
public sealed record DefenderStatus(
    string RunningMode,
    bool AntivirusEnabled,
    bool RealTimeProtection,
    DateTime? SignaturesUpdated,
    string? Version)
{
    /// <summary>Defender is the active antivirus (not standing by for another product).</summary>
    public bool IsActive => RunningMode.Equals("Normal", StringComparison.OrdinalIgnoreCase);

    /// <summary>Protection the user should know is missing, or null when all is well.</summary>
    public string? Problem(DateTime now) =>
        !IsActive ? null
        : !AntivirusEnabled ? "Microsoft Defender Antivirus is turned off."
        : !RealTimeProtection ? "Real-time protection is turned off, so new files aren't scanned as they arrive."
        : SignaturesUpdated is { } updated && now - updated > TimeSpan.FromDays(7)
            ? $"Virus definitions are {(now - updated).TotalDays:F0} days old. Check that Windows Update works."
            : null;
}

/// <param name="Id">Stable per detection, for "new since last time" checks.</param>
/// <param name="Resources">Affected files, without Defender's "file:_" prefixes.</param>
public sealed record DefenderDetection(
    string Id,
    DateTime Time,
    string Threat,
    string Severity,
    IReadOnlyList<string> Resources,
    string? ProcessName,
    string Status)
{
    /// <summary>Defender didn't remove, quarantine or block it, so the threat may still be there.</summary>
    public bool IsUnresolved => Status is "Detected" or "Allowed" or "Abandoned" or "No action taken"
        || Status.Contains("failed", StringComparison.OrdinalIgnoreCase);
}

/// <summary>Reads Microsoft Defender's status and history (WMI) and runs on-demand scans (MpCmdRun).</summary>
public static partial class Defender
{
    private const string Namespace = @"root\Microsoft\Windows\Defender";

    public static string ScannerPath { get; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");

    /// <summary>Null when Defender isn't installed or its WMI provider is unavailable.</summary>
    public static DefenderStatus? ReadStatus()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(Namespace,
                "SELECT AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated, AMProductVersion FROM MSFT_MpComputerStatus");
            using var results = searcher.Get();
            foreach (var obj in results)
            {
                using (obj)
                {
                    return new DefenderStatus(
                        obj["AMRunningMode"] as string ?? "Normal",
                        obj["AntivirusEnabled"] as bool? ?? false,
                        obj["RealTimeProtectionEnabled"] as bool? ?? false,
                        ToDate(obj["AntivirusSignatureLastUpdated"]),
                        obj["AMProductVersion"] as string);
                }
            }
            return null;
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
        {
            return null;
        }
    }

    /// <summary>Defender's detection history, newest first. Empty when it can't be read.</summary>
    public static IReadOnlyList<DefenderDetection> ReadDetections()
    {
        try
        {
            var names = new Dictionary<long, (string Name, string Severity)>();
            using (var threats = new ManagementObjectSearcher(Namespace, "SELECT ThreatID, ThreatName, SeverityID FROM MSFT_MpThreat"))
            using (var results = threats.Get())
            {
                foreach (var obj in results)
                {
                    using (obj)
                        names[Convert.ToInt64(obj["ThreatID"])] = (obj["ThreatName"] as string ?? "Unknown threat", Severity(obj["SeverityID"]));
                }
            }

            var detections = new List<DefenderDetection>();
            using (var searcher = new ManagementObjectSearcher(Namespace,
                "SELECT DetectionID, ThreatID, InitialDetectionTime, Resources, ProcessName, ThreatStatusID FROM MSFT_MpThreatDetection"))
            using (var results = searcher.Get())
            {
                foreach (var obj in results)
                {
                    using (obj)
                    {
                        var threatId = Convert.ToInt64(obj["ThreatID"]);
                        var (name, severity) = names.GetValueOrDefault(threatId, ($"Threat {threatId}", "Unknown"));
                        var time = ToDate(obj["InitialDetectionTime"]) ?? DateTime.MinValue;
                        detections.Add(new DefenderDetection(
                            obj["DetectionID"] as string ?? $"{threatId}@{time:O}",
                            time,
                            name,
                            severity,
                            ((obj["Resources"] as string[]) ?? []).Select(CleanResource).ToList(),
                            NullIfUnknown(obj["ProcessName"] as string),
                            Status(Convert.ToInt32(obj["ThreatStatusID"] ?? 0))));
                    }
                }
            }
            return detections.OrderByDescending(d => d.Time).ToList();
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
        {
            return [];
        }
    }

    /// <summary>
    /// Scans one file with Defender without letting it quarantine anything, so the user stays
    /// in control. Takes a few seconds; large archives take longer.
    /// </summary>
    /// <exception cref="InvalidOperationException">Defender's scanner is missing or failed.</exception>
    public static async Task<DefenderScanResult> ScanFileAsync(string path, CancellationToken ct = default)
    {
        if (!File.Exists(ScannerPath))
            throw new InvalidOperationException("Microsoft Defender's scanner (MpCmdRun.exe) isn't installed on this PC.");

        var startInfo = new ProcessStartInfo(ScannerPath)
        {
            ArgumentList = { "-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation" },
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Could not start Microsoft Defender's scanner.");
        var output = process.StandardOutput.ReadToEndAsync(ct);
        _ = process.StandardError.ReadToEndAsync(ct);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromMinutes(5));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill();
            throw new InvalidOperationException("The Defender scan took too long and was stopped.");
        }

        return ParseScan(process.ExitCode, await output, DateTime.Now);
    }

    /// <summary>MpCmdRun exits with 0 for a clean file and 2 when it found threats.</summary>
    internal static DefenderScanResult ParseScan(int exitCode, string output, DateTime scannedAt)
    {
        switch (exitCode)
        {
            case 0:
                return new DefenderScanResult(scannedAt, null);
            case 2:
                var threats = ThreatLine().Matches(output).Select(m => m.Groups[1].Value.Trim()).Distinct().ToList();
                return new DefenderScanResult(scannedAt, threats.Count > 0 ? string.Join(", ", threats) : "a threat");
            default:
                var reason = output.Split('\n').Select(l => l.Trim()).LastOrDefault(l => l.Length > 0);
                throw new InvalidOperationException(
                    $"Defender couldn't scan the file (code 0x{exitCode:X8}){(reason is null ? "." : $": {reason}")}");
        }
    }

    internal static string CleanResource(string resource)
    {
        var marker = resource.IndexOf(":_", StringComparison.Ordinal);
        return marker >= 0 ? resource[(marker + 2)..] : resource;
    }

    private static string Severity(object? id) => Convert.ToInt32(id ?? 0) switch
    {
        1 => "Low",
        2 => "Moderate",
        4 => "High",
        5 => "Severe",
        _ => "Unknown",
    };

    private static string Status(int id) => id switch
    {
        1 => "Detected",
        2 => "Cleaned",
        3 => "Quarantined",
        4 => "Removed",
        5 => "Allowed",
        6 => "Blocked",
        102 => "Quarantine failed",
        103 => "Removal failed",
        104 => "Allow failed",
        105 => "Abandoned",
        // Not in Microsoft's list, but seen with cleaning action 9 ("no action") on threats the user let be.
        106 => "No action taken",
        107 => "Block failed",
        _ => $"Status {id}",
    };

    private static string? NullIfUnknown(string? value) =>
        string.IsNullOrWhiteSpace(value) || value.Equals("Unknown", StringComparison.OrdinalIgnoreCase) ? null : value;

    private static DateTime? ToDate(object? value) => value switch
    {
        string dmtf when dmtf.Length > 0 => ManagementDateTimeConverter.ToDateTime(dmtf),
        DateTime date => date,
        _ => null,
    };

    [GeneratedRegex(@"^\s*Threat\s*:\s*(.+)$", RegexOptions.Multiline)]
    private static partial Regex ThreatLine();
}
