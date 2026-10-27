using System.IO;
using System.Text.Json;

namespace ThermoForge.UI.Services;

/// <summary>User preferences, saved as JSON next to the crash log.</summary>
public sealed class AppSettings
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static string FilePath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ThermoForge", "settings.json");

    /// <summary>Pop up a notification when a process reaches Medium or High risk.</summary>
    public bool NotifyProcesses { get; set; } = true;

    /// <summary>Pop up a notification when a CPU, GPU or drive stays too hot.</summary>
    public bool NotifyTemperature { get; set; } = true;

    /// <summary>Pop up a notification when a new program is set to start with Windows.</summary>
    public bool NotifyStartup { get; set; } = true;

    /// <summary>Pop up a notification when Defender is switched off or finds a threat.</summary>
    public bool NotifySecurity { get; set; } = true;

    /// <summary>VirusTotal API key, encrypted with DPAPI for the current Windows user; see <see cref="ApiKey"/>.</summary>
    public string? VirusTotalKeyProtected { get; set; }

    /// <summary>Look for a new release on GitHub once a day.</summary>
    public bool CheckForUpdates { get; set; } = true;

    public DateTime? LastUpdateCheckUtc { get; set; }

    /// <summary>A release the user chose to skip; it isn't offered again (a newer one is).</summary>
    public string? SkippedUpdateVersion { get; set; }

    /// <summary>The window's close button hides to the tray instead of exiting.</summary>
    public bool CloseToTray { get; set; } = true;

    /// <summary>The "still running in the tray" tip has been shown once.</summary>
    public bool TrayHintShown { get; set; }

    public static AppSettings Load()
    {
        try
        {
            return File.Exists(FilePath)
                ? JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath)) ?? new()
                : new();
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            return new();
        }
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(this, JsonOptions));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Preferences are a convenience; failing to save them must not break monitoring.
        }
    }
}
