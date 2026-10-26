using Microsoft.Win32;
using ThermoForge.Core.Processes;

namespace ThermoForge.Core.Startup;

internal static class Reg
{
    public static RegistryKey Base(string hive) => RegistryKey.OpenBaseKey(
        hive == "HKCU" ? RegistryHive.CurrentUser : RegistryHive.LocalMachine, RegistryView.Registry64);

    public static RegistryKey? Open(string hive, string path)
    {
        try
        {
            return Base(hive).OpenSubKey(path);
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>Opens a sub-key for reading; null when missing or locked (some services deny even reads).</summary>
    public static RegistryKey? OpenSub(RegistryKey parent, string name)
    {
        try
        {
            return parent.OpenSubKey(name);
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    public static string? String(RegistryKey key, string name) =>
        key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
}

/// <summary>
/// Task Manager's Startup tab doesn't delete entries it disables: it records the state in
/// <c>...\Explorer\StartupApproved</c>. ThermoForge reads and writes the same values, so the two
/// always agree and every change can be undone in either.
/// </summary>
public static class StartupApproval
{
    public const string BasePath = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";

    /// <summary>The first byte's low bit marks "disabled" (0x02/0x06 enabled, 0x03/0x07 disabled).</summary>
    public static bool IsEnabledValue(byte[]? value) => value is not { Length: > 0 } || (value[0] & 1) == 0;

    public static byte[] MakeValue(bool enabled, DateTime nowUtc)
    {
        var value = new byte[12];
        value[0] = enabled ? (byte)0x02 : (byte)0x03;
        if (!enabled)
            BitConverter.GetBytes(nowUtc.ToFileTimeUtc()).CopyTo(value, 4);
        return value;
    }

    public static bool IsEnabled(string hive, string subKey, string valueName)
    {
        using var key = Reg.Open(hive, $@"{BasePath}\{subKey}");
        return IsEnabledValue(key?.GetValue(valueName) as byte[]);
    }
}

/// <summary>The Run / RunOnce keys: the most common way programs (and malware) start at sign-in.</summary>
public sealed class RunKeySource : IStartupSource
{
    private const string CurrentVersion = @"Software\Microsoft\Windows\CurrentVersion";
    private const string Wow64CurrentVersion = @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion";

    /// <summary>Key, and the StartupApproved sub-key that can disable its entries (null: can't be toggled).</summary>
    private static readonly (string Hive, string Path, string? Approved)[] Keys =
    [
        ("HKCU", $@"{CurrentVersion}\Run", "Run"),
        ("HKCU", $@"{CurrentVersion}\RunOnce", null),
        ("HKCU", $@"{CurrentVersion}\Policies\Explorer\Run", null),
        ("HKLM", $@"{CurrentVersion}\Run", "Run"),
        ("HKLM", $@"{CurrentVersion}\RunOnce", null),
        ("HKLM", $@"{CurrentVersion}\Policies\Explorer\Run", null),
        ("HKLM", $@"{Wow64CurrentVersion}\Run", "Run32"),
        ("HKLM", $@"{Wow64CurrentVersion}\RunOnce", null),
    ];

    public IEnumerable<RawStartupEntry> Read(ICollection<string> errors)
    {
        foreach (var (hive, path, approved) in Keys)
        {
            using var key = Reg.Open(hive, path);
            if (key is null)
                continue;

            foreach (var name in key.GetValueNames().Where(n => n.Length > 0))
            {
                yield return new RawStartupEntry(
                    StartupSource.RunKey,
                    name,
                    $@"{hive}\{path}",
                    Reg.String(key, name),
                    Enabled: approved is null || StartupApproval.IsEnabled(hive, approved, name),
                    Toggle: approved is null ? null : new StartupToggle(StartupToggleKind.StartupApproved, $@"{StartupApproval.BasePath}\{approved}", hive, name));
            }
        }
    }
}

/// <summary>Services and drivers that start with Windows (boot, system and automatic start types).</summary>
public sealed class ServiceSource : IStartupSource
{
    private const string ServicesPath = @"SYSTEM\CurrentControlSet\Services";
    private const int StartAutomatic = 2;
    private const int DriverTypes = 0x1 | 0x2 | 0x8; // kernel, file system, recognizer drivers

    public IEnumerable<RawStartupEntry> Read(ICollection<string> errors)
    {
        using var services = Reg.Open("HKLM", ServicesPath);
        if (services is null)
        {
            errors.Add("Services could not be read.");
            yield break;
        }

        var denied = 0;
        foreach (var name in services.GetSubKeyNames())
        {
            using var key = Reg.OpenSub(services, name);
            if (key is null)
            {
                denied++;
                continue;
            }
            if (key.GetValue("Start") is not int start || start > StartAutomatic)
                continue;
            var command = Reg.String(key, "ImagePath");
            if (string.IsNullOrWhiteSpace(command))
                continue;

            var type = key.GetValue("Type") is int t ? t : 0;
            var isDriver = (type & DriverTypes) != 0;

            // Shared-process services run inside svchost.exe; their real code is the ServiceDll.
            using var parameters = Reg.OpenSub(key, "Parameters");
            var serviceDll = (parameters is null ? null : Reg.String(parameters, "ServiceDll")) ?? Reg.String(key, "ServiceDll");

            var displayName = Reg.String(key, "DisplayName");
            yield return new RawStartupEntry(
                isDriver ? StartupSource.Driver : StartupSource.Service,
                name,
                $@"HKLM\{ServicesPath}\{name}",
                command,
                Description: displayName is null || displayName.StartsWith('@') ? null : displayName,
                ImagePath: serviceDll is null ? null : Environment.ExpandEnvironmentVariables(serviceDll));
        }

        if (denied > 0)
            errors.Add($"{denied} service{(denied == 1 ? "" : "s")} hidden by Windows");
    }
}

/// <summary>
/// Winlogon's Shell and Userinit values decide what runs when anyone signs in. Malware edits them
/// to start before (or instead of) the normal desktop.
/// </summary>
public sealed class WinlogonSource : IStartupSource
{
    private const string WinlogonPath = @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon";

    public IEnumerable<RawStartupEntry> Read(ICollection<string> errors)
    {
        var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        foreach (var hive in new[] { "HKLM", "HKCU" })
        {
            using var key = Reg.Open(hive, WinlogonPath);
            if (key is null)
                continue;

            if (Reg.String(key, "Shell") is { } shell)
                yield return Entry(hive, "Shell", shell, IsDefaultShell(shell) ? null : new ProcessFinding(FindingSeverity.High,
                    "Replaces the Windows shell",
                    $"Windows normally starts explorer.exe as the desktop. This entry starts \"{shell}\" instead or as well, a known way for malware to run at every sign-in."));

            // Only the machine-wide value is used for Userinit.
            if (hive == "HKLM" && Reg.String(key, "Userinit") is { } userinit)
                yield return Entry(hive, "Userinit", userinit.TrimEnd(','), IsDefaultUserinit(userinit, system32) ? null : new ProcessFinding(FindingSeverity.High,
                    "Adds a program to every sign-in",
                    $"Userinit should only start userinit.exe. Extra programs here run for every user at sign-in: \"{userinit}\"."));
        }
    }

    internal static bool IsDefaultShell(string value) =>
        value.Trim().TrimEnd(',').Equals("explorer.exe", StringComparison.OrdinalIgnoreCase);

    internal static bool IsDefaultUserinit(string value, string system32) =>
        value.Trim().TrimEnd(',').Trim() is var v
        && (v.Equals(Path.Combine(system32, "userinit.exe"), StringComparison.OrdinalIgnoreCase)
            || v.Equals("userinit.exe", StringComparison.OrdinalIgnoreCase));

    private static RawStartupEntry Entry(string hive, string name, string command, ProcessFinding? finding) => new(
        StartupSource.Winlogon,
        $"Winlogon {name}",
        $@"{hive}\{WinlogonPath}",
        command,
        SourceFindings: finding is null ? null : [finding]);
}

/// <summary>
/// Image File Execution Options "Debugger" and SilentProcessExit "MonitorProcess" make Windows
/// run another program whenever a given program starts or exits. Malware uses them to launch
/// itself or to stop security tools from opening.
/// </summary>
public sealed class LaunchHijackSource : IStartupSource
{
    private const string Ifeo = @"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    private const string Wow64Ifeo = @"Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    private const string SilentExit = @"Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit";

    public IEnumerable<RawStartupEntry> Read(ICollection<string> errors)
    {
        foreach (var root in new[] { Ifeo, Wow64Ifeo })
        {
            foreach (var (program, debugger) in Values(root, "Debugger"))
            {
                yield return new RawStartupEntry(StartupSource.LaunchHijack, $"{program} → debugger", $@"HKLM\{root}\{program}", debugger,
                    SourceFindings: [new(FindingSeverity.High, $"Hijacks {program}",
                        $"Whenever {program} is started, Windows runs this program instead. Debugging tools set this briefly; malware uses it to start itself or to block security tools.")]);
            }
        }

        foreach (var (program, monitor) in Values(SilentExit, "MonitorProcess"))
        {
            yield return new RawStartupEntry(StartupSource.LaunchHijack, $"{program} → on exit", $@"HKLM\{SilentExit}\{program}", monitor,
                SourceFindings: [new(FindingSeverity.High, $"Runs whenever {program} exits",
                    $"Windows starts this program every time {program} closes. This is rarely used legitimately and is a known persistence trick.")]);
        }
    }

    private static IEnumerable<(string Program, string Value)> Values(string root, string valueName)
    {
        using var key = Reg.Open("HKLM", root);
        if (key is null)
            yield break;

        foreach (var program in key.GetSubKeyNames())
        {
            using var sub = Reg.OpenSub(key, program);
            if (sub is not null && Reg.String(sub, valueName) is { Length: > 0 } value)
                yield return (program, value);
        }
    }
}
