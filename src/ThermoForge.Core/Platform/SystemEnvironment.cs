using System.Runtime.InteropServices;
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

    /// <summary>Time since the last keyboard or mouse input in this Windows session.</summary>
    public static TimeSpan UserIdleTime()
    {
        var info = new LastInputInfo { Size = (uint)Marshal.SizeOf<LastInputInfo>() };
        if (!GetLastInputInfo(ref info))
            return TimeSpan.Zero;

        // Both are 32-bit millisecond tick counts; unsigned subtraction handles the 49-day wrap.
        return TimeSpan.FromMilliseconds(unchecked((uint)Environment.TickCount - info.Time));
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LastInputInfo
    {
        public uint Size;
        public uint Time;
    }

    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern bool GetLastInputInfo(ref LastInputInfo info);
}
