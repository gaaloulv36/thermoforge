using System.Diagnostics;
using System.Security.Principal;
using System.Text;
using System.Xml.Linq;

namespace ThermoForge.Core.Platform;

public enum AutoStartState
{
    Off,
    On,

    /// <summary>The task exists but starts a ThermoForge.exe somewhere else (e.g. an older copy).</summary>
    OnOtherPath,
}

/// <summary>
/// "Start with Windows": a Task Scheduler task that starts ThermoForge in the tray when the user
/// signs in, with the highest privileges available. Admins get full sensor and process access
/// without a UAC prompt every time, which a Run key can't do. Changing it requires admin rights.
/// </summary>
public static class AutoStart
{
    public const string TaskName = "ThermoForge";

    /// <summary>Command-line switch: start hidden in the notification area.</summary>
    public const string TrayArgument = "--tray";

    private static readonly XNamespace Ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    public static AutoStartState Query(string exePath)
    {
        var (exitCode, output) = RunSchtasks("/Query", "/TN", TaskName, "/XML", "ONE");
        if (exitCode != 0)
            return AutoStartState.Off;

        var command = ParseCommand(output);
        return string.Equals(command, exePath, StringComparison.OrdinalIgnoreCase) ? AutoStartState.On : AutoStartState.OnOtherPath;
    }

    /// <exception cref="InvalidOperationException">Not elevated, or Task Scheduler refused.</exception>
    public static void Enable(string exePath)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var file = Path.Combine(Path.GetTempPath(), $"thermoforge-task-{Guid.NewGuid():N}.xml");
        try
        {
            // schtasks reads UTF-16 task XML reliably.
            File.WriteAllText(file, TaskXml(exePath, identity.User!.Value), Encoding.Unicode);
            var (exitCode, output) = RunSchtasks("/Create", "/TN", TaskName, "/XML", file, "/F");
            if (exitCode != 0)
                throw new InvalidOperationException($"Task Scheduler refused to create the task: {output.Trim()}");
        }
        finally
        {
            File.Delete(file);
        }
    }

    /// <exception cref="InvalidOperationException">Not elevated, or Task Scheduler refused.</exception>
    public static void Disable()
    {
        var (exitCode, output) = RunSchtasks("/Delete", "/TN", TaskName, "/F");
        // Failing because the task is already gone is fine.
        if (exitCode != 0 && Query(exePath: "") != AutoStartState.Off)
            throw new InvalidOperationException($"Task Scheduler refused to remove the task: {output.Trim()}");
    }

    /// <param name="userSid">The user whose sign-in starts the task, and who it runs as.</param>
    internal static string TaskXml(string exePath, string userSid)
    {
        var task = new XElement(Ns + "Task", new XAttribute("version", "1.2"),
            new XElement(Ns + "RegistrationInfo",
                new XElement(Ns + "Author", "Forge Studio"),
                new XElement(Ns + "Description",
                    "Starts ThermoForge in the notification area when you sign in, with administrator rights so every sensor and process is visible."),
                new XElement(Ns + "URI", @"\" + TaskName)),
            new XElement(Ns + "Triggers",
                new XElement(Ns + "LogonTrigger",
                    new XElement(Ns + "Enabled", "true"),
                    new XElement(Ns + "UserId", userSid),
                    // Let the desktop and tray settle first.
                    new XElement(Ns + "Delay", "PT10S"))),
            new XElement(Ns + "Principals",
                new XElement(Ns + "Principal", new XAttribute("id", "Author"),
                    new XElement(Ns + "UserId", userSid),
                    new XElement(Ns + "LogonType", "InteractiveToken"),
                    new XElement(Ns + "RunLevel", "HighestAvailable"))),
            new XElement(Ns + "Settings",
                new XElement(Ns + "MultipleInstancesPolicy", "IgnoreNew"),
                // Laptops are the main audience: keep watching on battery.
                new XElement(Ns + "DisallowStartIfOnBatteries", "false"),
                new XElement(Ns + "StopIfGoingOnBatteries", "false"),
                new XElement(Ns + "AllowHardTerminate", "true"),
                new XElement(Ns + "StartWhenAvailable", "false"),
                new XElement(Ns + "RunOnlyIfNetworkAvailable", "false"),
                new XElement(Ns + "IdleSettings",
                    new XElement(Ns + "StopOnIdleEnd", "false"),
                    new XElement(Ns + "RestartOnIdle", "false")),
                new XElement(Ns + "AllowStartOnDemand", "true"),
                new XElement(Ns + "Enabled", "true"),
                new XElement(Ns + "Hidden", "false"),
                new XElement(Ns + "RunOnlyIfIdle", "false"),
                // Runs until the user exits it; the default would stop it after 3 days.
                new XElement(Ns + "ExecutionTimeLimit", "PT0S"),
                new XElement(Ns + "Priority", "5")),
            new XElement(Ns + "Actions", new XAttribute("Context", "Author"),
                new XElement(Ns + "Exec",
                    new XElement(Ns + "Command", exePath),
                    new XElement(Ns + "Arguments", TrayArgument))));

        return new XDocument(new XDeclaration("1.0", "UTF-16", null), task).ToString();
    }

    /// <summary>The program a task XML starts, or null if it has none.</summary>
    internal static string? ParseCommand(string taskXml)
    {
        try
        {
            return XDocument.Parse(taskXml).Descendants(Ns + "Command").FirstOrDefault()?.Value.Trim().Trim('"');
        }
        catch (System.Xml.XmlException)
        {
            return null;
        }
    }

    private static (int ExitCode, string Output) RunSchtasks(params string[] arguments)
    {
        var startInfo = new ProcessStartInfo("schtasks.exe")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in arguments)
            startInfo.ArgumentList.Add(argument);

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start schtasks.exe.");
        var error = process.StandardError.ReadToEndAsync();
        var output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode, output + error.Result);
    }
}
