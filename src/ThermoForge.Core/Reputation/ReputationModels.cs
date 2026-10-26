using System.Globalization;
using ThermoForge.Core.Processes;

namespace ThermoForge.Core.Reputation;

public enum VirusTotalVerdict
{
    /// <summary>VirusTotal has never seen the file.</summary>
    NotFound,
    Clean,
    Suspicious,
    Malicious,
}

/// <param name="Engines">Antivirus engines that gave a verdict in the latest analysis.</param>
/// <param name="ThreatLabel">VirusTotal's suggested name for the threat, e.g. "trojan.coinminer/xmrig".</param>
/// <param name="LastAnalysis">When VirusTotal last analysed the file (not when we asked).</param>
public sealed record VirusTotalReport(
    VirusTotalVerdict Verdict,
    int Malicious,
    int Suspicious,
    int Engines,
    string? ThreatLabel,
    DateTime? LastAnalysis,
    DateTime CheckedAt)
{
    public static VirusTotalReport NotFound(DateTime checkedAt) => new(VirusTotalVerdict.NotFound, 0, 0, 0, null, null, checkedAt);
}

/// <param name="Threat">What Defender detected; null when the file is clean.</param>
public sealed record DefenderScanResult(DateTime ScannedAt, string? Threat);

/// <summary>What outside scanners said about one exact file (by SHA-256).</summary>
/// <param name="Path">Where the file was when it was last checked.</param>
public sealed record FileReputation(string Sha256, string Path, VirusTotalReport? VirusTotal, DefenderScanResult? Defender)
{
    /// <summary>Detections become findings, so they count toward the risk score and raise alerts.</summary>
    public IReadOnlyList<ProcessFinding> Findings()
    {
        var findings = new List<ProcessFinding>();
        if (Defender?.Threat is { } threat)
            findings.Add(new(FindingSeverity.High, $"Microsoft Defender detects this as {threat}",
                "Windows' own antivirus identified this file as a threat when ThermoForge asked it to scan the file."));

        if (VirusTotal is { } vt)
        {
            var label = vt.ThreatLabel is { } name ? $" Most engines call it \"{name}\"." : "";
            if (vt.Malicious > 0)
            {
                var severity = vt.Malicious >= 5 ? FindingSeverity.High
                    : vt.Malicious >= 2 ? FindingSeverity.Medium
                    : FindingSeverity.Low;
                findings.Add(new(severity, $"VirusTotal: {vt.Malicious} of {vt.Engines} antivirus engines detect this",
                    severity == FindingSeverity.Low
                        ? "A single engine on its own is often a false positive, especially for small or new tools." + label
                        : "Several antivirus products independently flag this exact file." + label));
            }
            else if (vt.Suspicious > 0)
            {
                findings.Add(new(FindingSeverity.Low, $"VirusTotal: {vt.Suspicious} of {vt.Engines} engines find this suspicious",
                    "No engine calls it malware, but some find it unusual."));
            }
        }
        return findings;
    }

    /// <summary>One line per scanner, for the details panes.</summary>
    public string Summary
    {
        get
        {
            var lines = new List<string>();
            if (VirusTotal is { } vt)
            {
                var when = Format(vt.CheckedAt);
                lines.Add(vt.Verdict switch
                {
                    VirusTotalVerdict.NotFound => $"VirusTotal has never seen this file (checked {when}). Not proof of anything: most private or new tools are unknown.",
                    VirusTotalVerdict.Clean => $"VirusTotal: no engine detects this file (0 of {vt.Engines}, checked {when}).",
                    _ => $"VirusTotal: {vt.Malicious} malicious, {vt.Suspicious} suspicious, out of {vt.Engines} engines (checked {when}).",
                });
            }
            if (Defender is { } defender)
            {
                lines.Add(defender.Threat is { } threat
                    ? $"Microsoft Defender: {threat} (scanned {Format(defender.ScannedAt)})."
                    : $"Microsoft Defender: no threat found (scanned {Format(defender.ScannedAt)}).");
            }
            return string.Join(Environment.NewLine, lines);
        }
    }

    private static string Format(DateTime time) => time.ToString("g", CultureInfo.CurrentCulture);
}
