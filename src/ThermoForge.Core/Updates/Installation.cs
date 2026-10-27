using Microsoft.Win32;

namespace ThermoForge.Core.Updates;

/// <summary>
/// Whether this copy was installed by ThermoForge-Setup (which can update it in place) rather than
/// run from the portable zip or a development build (which the installer would not replace).
/// </summary>
public static class Installation
{
    /// <summary>Inno Setup's uninstall key for installer/ThermoForge.iss's AppId.</summary>
    private const string UninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{312C1079-C50B-4581-8EB3-203D49286E21}_is1";

    public static string? InstallFolder()
    {
        using var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = hive.OpenSubKey(UninstallKey);
        return key?.GetValue("InstallLocation") as string;
    }

    public static bool IsInstalledCopy(string exePath) => IsInside(exePath, InstallFolder());

    internal static bool IsInside(string exePath, string? folder) =>
        folder is { Length: > 0 }
        && string.Equals(
            Path.GetFullPath(Path.GetDirectoryName(exePath)!).TrimEnd('\\'),
            Path.GetFullPath(folder).TrimEnd('\\'),
            StringComparison.OrdinalIgnoreCase);
}
