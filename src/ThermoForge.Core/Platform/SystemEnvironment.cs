using System.Security.Principal;
using Microsoft.Win32;

namespace ThermoForge.Core.Platform;

public static class SystemEnvironment
{
    public const string PawnIoDownloadUrl = "https://pawnio.eu/";

    public static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>
    /// LibreHardwareMonitor uses the PawnIO kernel driver for CPU (MSR) and embedded-controller
    /// sensors. The driver is installed system-wide by its own setup, which registers this service key.
    /// </summary>
    public static bool IsPawnIoInstalled()
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\PawnIO");
        return key is not null;
    }
}
