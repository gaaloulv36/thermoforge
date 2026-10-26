using System.Security.Cryptography;
using System.Text;
using ThermoForge.Core.Processes;

namespace ThermoForge.Core.Startup;

/// <summary>Where Windows keeps an auto-start entry.</summary>
public enum StartupSource
{
    RunKey,
    StartupFolder,
    ScheduledTask,
    Service,
    Driver,
    Winlogon,
    LaunchHijack,
    WmiSubscription,
}

/// <summary>How an entry can be switched off and on again, the way Task Manager / Task Scheduler do it.</summary>
/// <param name="Hive">"HKCU" or "HKLM", for <see cref="StartupToggleKind.StartupApproved"/>.</param>
/// <param name="KeyPath">Registry key under the hive (StartupApproved) or the task's full path (ScheduledTask).</param>
/// <param name="ValueName">The value inside <paramref name="KeyPath"/> (StartupApproved only).</param>
public sealed record StartupToggle(StartupToggleKind Kind, string KeyPath, string? Hive = null, string? ValueName = null);

public enum StartupToggleKind
{
    StartupApproved,
    ScheduledTask,
}

/// <summary>An auto-start entry as Windows stores it, before analysis.</summary>
/// <param name="Location">Human-readable place it lives, e.g. <c>HKCU\Software\Microsoft\Windows\CurrentVersion\Run</c>.</param>
/// <param name="Command">The command line Windows runs, as configured.</param>
/// <param name="ImagePath">The file that actually runs when it isn't the command's program (e.g. a service DLL).</param>
/// <param name="SourceFindings">Findings that come from where the entry is, not from its file (e.g. a hijacked Winlogon shell).</param>
public sealed record RawStartupEntry(
    StartupSource Source,
    string Name,
    string Location,
    string? Command,
    bool Enabled = true,
    string? Description = null,
    string? ImagePath = null,
    IReadOnlyList<ProcessFinding>? SourceFindings = null,
    StartupToggle? Toggle = null)
{
    /// <summary>
    /// Stable identity across scans. Includes the command, so an existing entry that is
    /// changed to run something else counts as new.
    /// </summary>
    public string Id { get; } = MakeId(Source, Location, Name, Command);

    private static string MakeId(StartupSource source, string location, string name, string? command)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes($"{source}|{location}|{name}|{command}".ToUpperInvariant()));
        return Convert.ToHexString(hash, 0, 12);
    }
}

/// <param name="ImagePath">The file the entry runs, resolved from its command; null when it can't be worked out.</param>
/// <param name="FileMissing">The entry points to a file that doesn't exist.</param>
/// <param name="IsNew">First seen after ThermoForge's first scan, within the last week.</param>
public sealed record StartupEntry(
    RawStartupEntry Raw,
    string? ImagePath,
    bool FileMissing,
    FileMetadata? File,
    IReadOnlyList<ProcessFinding> Findings,
    bool IsTrusted,
    DateTime FirstSeen,
    bool IsNew)
{
    public int Risk => IsTrusted ? 0 : RiskScore.From(Findings);

    public FindingSeverity Severity => RiskScore.Level(Risk);
}

/// <param name="Errors">Sources that couldn't be read fully, in plain language.</param>
public sealed record StartupScan(DateTime Timestamp, IReadOnlyList<StartupEntry> Entries, IReadOnlyList<string> Errors);

/// <summary>One place auto-start entries are read from.</summary>
public interface IStartupSource
{
    /// <param name="errors">Problems that don't stop the rest of this source, e.g. tasks Windows won't show without admin rights.</param>
    IEnumerable<RawStartupEntry> Read(ICollection<string> errors);
}
