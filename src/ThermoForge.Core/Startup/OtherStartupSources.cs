using System.Management;
using System.Runtime.InteropServices;
using ThermoForge.Core.Processes;

namespace ThermoForge.Core.Startup;

/// <summary>Shortcuts and files in the per-user and all-users Startup folders.</summary>
public sealed class StartupFolderSource : IStartupSource
{
    public IEnumerable<RawStartupEntry> Read(ICollection<string> errors)
    {
        foreach (var (folder, hive) in new[]
                 {
                     (Environment.GetFolderPath(Environment.SpecialFolder.Startup), "HKCU"),
                     (Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "HKLM"),
                 })
        {
            if (!Directory.Exists(folder))
                continue;

            foreach (var file in Directory.EnumerateFiles(folder))
            {
                var name = Path.GetFileName(file);
                if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase))
                    continue;

                yield return new RawStartupEntry(
                    StartupSource.StartupFolder,
                    Path.GetFileNameWithoutExtension(file),
                    folder,
                    CommandFor(file),
                    Enabled: StartupApproval.IsEnabled(hive, "StartupFolder", name),
                    Toggle: new StartupToggle(StartupToggleKind.StartupApproved, $@"{StartupApproval.BasePath}\StartupFolder", hive, name));
            }
        }
    }

    /// <summary>A shortcut runs its target; any other file is opened directly.</summary>
    private static string CommandFor(string file)
    {
        if (!file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
            return $"\"{file}\"";

        try
        {
            dynamic shell = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell")!)!;
            try
            {
                dynamic link = shell.CreateShortcut(file);
                string target = link.TargetPath;
                string arguments = link.Arguments;
                // Installer-advertised shortcuts have no target path; fall back to the shortcut itself.
                return string.IsNullOrEmpty(target) ? $"\"{file}\"" : $"\"{target}\" {arguments}".Trim();
            }
            finally
            {
                Marshal.FinalReleaseComObject(shell);
            }
        }
        catch (Exception ex) when (ex is COMException or InvalidCastException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
        {
            return $"\"{file}\"";
        }
    }
}

/// <summary>
/// Scheduled tasks that run a program. Windows hides some tasks' details from non-admin users;
/// those are counted and reported rather than silently skipped.
/// </summary>
public sealed class ScheduledTaskSource : IStartupSource
{
    private const int ExecAction = 0;
    private const int IncludeHidden = 1;

    public IEnumerable<RawStartupEntry> Read(ICollection<string> errors)
    {
        var entries = new List<RawStartupEntry>();
        var denied = 0;
        dynamic? service = null;
        try
        {
            service = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service")!)!;
            service.Connect();
            Walk(service.GetFolder("\\"), entries, ref denied);
        }
        catch (Exception ex) when (ex is COMException or UnauthorizedAccessException)
        {
            errors.Add($"Scheduled tasks could not be read: {ex.Message}");
        }
        finally
        {
            if (service is not null)
                Marshal.FinalReleaseComObject(service);
        }

        if (denied > 0)
            errors.Add($"{denied} scheduled task{(denied == 1 ? "" : "s")} hidden by Windows (run as administrator to check them)");
        return entries;
    }

    private static void Walk(dynamic folder, List<RawStartupEntry> entries, ref int denied)
    {
        foreach (dynamic task in folder.GetTasks(IncludeHidden))
        {
            try
            {
                string path = task.Path;
                string name = task.Name;
                bool enabled = task.Enabled;
                foreach (dynamic action in task.Definition.Actions)
                {
                    if ((int)action.Type != ExecAction)
                        continue;
                    string program = action.Path ?? "";
                    string arguments = action.Arguments ?? "";
                    var command = (program.Contains(' ') && !program.StartsWith('"') ? $"\"{program}\"" : program) + " " + arguments;

                    entries.Add(new RawStartupEntry(
                        StartupSource.ScheduledTask,
                        name,
                        Path.GetDirectoryName(path) is { Length: > 0 } dir ? $"Task Scheduler {dir}" : "Task Scheduler \\",
                        command.Trim(),
                        Enabled: enabled,
                        Toggle: new StartupToggle(StartupToggleKind.ScheduledTask, path)));
                }
            }
            catch (Exception ex) when (ex is COMException or UnauthorizedAccessException)
            {
                denied++;
            }
        }

        foreach (dynamic sub in folder.GetFolders(0))
            Walk(sub, entries, ref denied);
    }
}

/// <summary>
/// Permanent WMI event subscriptions that run a command or script. They survive reboots, leave
/// no file in any Startup folder, and are a favourite of "fileless" malware.
/// </summary>
public sealed class WmiSubscriptionSource : IStartupSource
{
    public IEnumerable<RawStartupEntry> Read(ICollection<string> errors)
    {
        var entries = new List<RawStartupEntry>();
        try
        {
            using (var commands = new ManagementObjectSearcher(@"root\subscription", "SELECT Name, CommandLineTemplate, ExecutablePath FROM CommandLineEventConsumer"))
            using (var results = commands.Get())
            {
                foreach (var obj in results)
                {
                    using (obj)
                    {
                        var command = obj["CommandLineTemplate"] as string ?? obj["ExecutablePath"] as string;
                        entries.Add(Entry(obj["Name"] as string ?? "(unnamed)", command, "Runs a command on a WMI event",
                            "A permanent WMI subscription runs this command when a system event happens (often at startup or on a timer). Some vendor tools use this, but it is a common hiding place for fileless malware."));
                    }
                }
            }

            using (var scripts = new ManagementObjectSearcher(@"root\subscription", "SELECT Name, ScriptFileName, ScriptingEngine FROM ActiveScriptEventConsumer"))
            using (var results = scripts.Get())
            {
                foreach (var obj in results)
                {
                    using (obj)
                    {
                        var file = obj["ScriptFileName"] as string;
                        entries.Add(Entry(obj["Name"] as string ?? "(unnamed)", file ?? $"(inline {obj["ScriptingEngine"]} script)", "Runs a script on a WMI event",
                            "A permanent WMI subscription runs a script when a system event happens. This is very rarely legitimate."));
                    }
                }
            }
        }
        catch (ManagementException ex)
        {
            errors.Add($"WMI subscriptions could not be read ({ex.ErrorCode}); run as administrator to check them.");
        }
        catch (UnauthorizedAccessException)
        {
            errors.Add("WMI subscriptions are hidden by Windows; run as administrator to check them.");
        }
        return entries;
    }

    private static RawStartupEntry Entry(string name, string? command, string title, string detail) => new(
        StartupSource.WmiSubscription,
        name,
        @"WMI root\subscription",
        command,
        SourceFindings: [new(FindingSeverity.High, title, detail)]);
}
