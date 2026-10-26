using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace ThermoForge.Core.Startup;

/// <summary>
/// Switches entries off and on without deleting anything, using the same mechanisms as Task
/// Manager (StartupApproved) and Task Scheduler (task enabled flag), so every change can be undone.
/// </summary>
public static class StartupControl
{
    public static bool CanToggle(RawStartupEntry entry) => entry.Toggle is not null;

    /// <exception cref="InvalidOperationException">With a user-readable message (e.g. needs administrator rights).</exception>
    public static void SetEnabled(RawStartupEntry entry, bool enabled)
    {
        var toggle = entry.Toggle ?? throw new InvalidOperationException($"{entry.Name} can't be switched off from ThermoForge.");
        try
        {
            switch (toggle.Kind)
            {
                case StartupToggleKind.StartupApproved:
                    using (var key = Reg.Base(toggle.Hive!).CreateSubKey(toggle.KeyPath, writable: true))
                        key.SetValue(toggle.ValueName!, StartupApproval.MakeValue(enabled, DateTime.UtcNow), RegistryValueKind.Binary);
                    break;

                case StartupToggleKind.ScheduledTask:
                    SetTaskEnabled(toggle.KeyPath, enabled);
                    break;
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException
                                       || (ex is COMException com && com.HResult == unchecked((int)0x80070005)))
        {
            throw new InvalidOperationException(
                $"Windows didn't allow changing {entry.Name}. Entries for all users need ThermoForge to run as administrator.", ex);
        }
        catch (COMException ex)
        {
            throw new InvalidOperationException($"Could not change {entry.Name}: {ex.Message}", ex);
        }
    }

    private static void SetTaskEnabled(string taskPath, bool enabled)
    {
        dynamic service = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service")!)!;
        try
        {
            service.Connect();
            dynamic folder = service.GetFolder(Path.GetDirectoryName(taskPath) is { Length: > 0 } dir ? dir : "\\");
            dynamic task = folder.GetTask(Path.GetFileName(taskPath));
            task.Enabled = enabled;
        }
        finally
        {
            Marshal.FinalReleaseComObject(service);
        }
    }
}
