using System.ComponentModel;
using System.Diagnostics;

namespace TempMonitor.Core.Processes;

public static class ProcessControl
{
    /// <summary>Ending any of these crashes or destabilises Windows, so the app refuses to.</summary>
    private static readonly HashSet<string> Critical = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Registry", "Memory Compression", "Secure System",
        "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
        "lsass.exe", "lsaiso.exe", "svchost.exe", "dwm.exe", "fontdrvhost.exe", "MsMpEng.exe",
    };

    public static bool IsCritical(RawProcess process) =>
        process.Pid == 4 || Critical.Contains(process.Name);

    /// <summary>Ends the process, after confirming its PID still belongs to the same process.</summary>
    /// <exception cref="InvalidOperationException">With a user-readable message when it cannot be ended.</exception>
    public static void Kill(RawProcess process)
    {
        if (IsCritical(process))
            throw new InvalidOperationException($"{process.Name} is a critical Windows process; ending it would crash the system.");

        try
        {
            using var target = Process.GetProcessById(process.Pid);
            // WMI start times are microsecond precision, Process.StartTime is 100 ns, so compare loosely.
            if (process.StartTime is { } expected && Math.Abs((target.StartTime - expected).TotalSeconds) > 1)
                throw new InvalidOperationException($"{process.Name} has already exited.");

            target.Kill();
            target.WaitForExit(TimeSpan.FromSeconds(3));
        }
        catch (ArgumentException)
        {
            throw new InvalidOperationException($"{process.Name} has already exited.");
        }
        catch (Win32Exception)
        {
            throw new InvalidOperationException(
                $"Windows denied access to {process.Name}. It may be protected, or the app needs to run as administrator.");
        }
    }
}
