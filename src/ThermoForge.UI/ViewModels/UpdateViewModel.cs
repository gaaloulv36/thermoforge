using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ThermoForge.Core.Updates;
using ThermoForge.UI.Services;

namespace ThermoForge.UI.ViewModels;

/// <summary>
/// Checks GitHub for a newer release (on its own once a day, or on request), shows a banner and a
/// notification, and installs the update: download, verify, run the installer silently, exit.
/// The installer reopens ThermoForge when it's done.
/// </summary>
public sealed partial class UpdateViewModel : ObservableObject, IDisposable
{
    private const int ErrorCancelled = 1223;
    private static readonly TimeSpan CheckEvery = TimeSpan.FromDays(1);
    private static readonly TimeSpan FirstCheckDelay = TimeSpan.FromSeconds(30);

    /// <summary>
    /// /SILENT shows only a progress window; previous choices (folder, start with Windows) are
    /// kept; the installer waits for ThermoForge to exit and reopens it afterwards.
    /// </summary>
    private const string InstallerArguments = "/SILENT /SUPPRESSMSGBOXES /NORESTART /NOCANCEL";

    private static readonly string DownloadFolder = Path.Combine(Path.GetTempPath(), "ThermoForge-Update");
    private static readonly HttpClient Http = CreateHttpClient();

    private readonly AppSettings _settings;
    private readonly UpdateChecker _checker;
    private readonly CancellationTokenSource _stop = new();
    private Version? _notifiedVersion;

    public UpdateViewModel(AppSettings settings)
    {
        _settings = settings;
        _checker = new UpdateChecker(Http, UpdateChecker.CurrentVersion());
        _checkAutomatically = settings.CheckForUpdates;
    }

    /// <summary>A newer version was found by a check (once per version per session).</summary>
    public event EventHandler<AvailableUpdate>? UpdateFound;

    /// <summary>The installer has started; ThermoForge must exit so it can replace the files.</summary>
    public event EventHandler? ExitForUpdate;

    public string CurrentVersionText => $"You have version {_checker.Current.ToString(3)}.";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsUpdateAvailable), nameof(AvailableText))]
    [NotifyCanExecuteChangedFor(nameof(InstallCommand), nameof(OpenReleaseNotesCommand), nameof(SkipVersionCommand))]
    private AvailableUpdate? _available;

    public bool IsUpdateAvailable => Available is not null;

    public string AvailableText => Available is { } update
        ? $"ThermoForge {update.Version.ToString(3)} is available"
          + (update.Published is { } date ? $" (released {date.ToString("d", CultureInfo.CurrentCulture)})." : ".")
        : "";

    [ObservableProperty]
    private bool _showBanner;

    [ObservableProperty]
    private string _statusText = "";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CheckNowCommand), nameof(InstallCommand))]
    private bool _isBusy;

    /// <summary>Download progress, 0–100.</summary>
    [ObservableProperty]
    private double _progress;

    [ObservableProperty]
    private bool _isDownloading;

    [ObservableProperty]
    private bool _checkAutomatically;

    partial void OnCheckAutomaticallyChanged(bool value)
    {
        _settings.CheckForUpdates = value;
        _settings.Save();
    }

    public void Start()
    {
        CleanUpOldDownloads();
        _ = CheckPeriodicallyAsync(_stop.Token);
    }

    public void Dispose() => _stop.Cancel();

    private async Task CheckPeriodicallyAsync(CancellationToken ct)
    {
        try
        {
            await Task.Delay(FirstCheckDelay, ct);
            while (!ct.IsCancellationRequested)
            {
                var due = _settings.LastUpdateCheckUtc is not { } last || DateTime.UtcNow - last >= CheckEvery;
                if (CheckAutomatically && due && !IsBusy)
                    await CheckAsync(manual: false);
                await Task.Delay(TimeSpan.FromHours(1), ct);
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    [RelayCommand(CanExecute = nameof(IsIdle))]
    private Task CheckNowAsync() => CheckAsync(manual: true);

    private bool IsIdle() => !IsBusy;

    private async Task CheckAsync(bool manual)
    {
        IsBusy = true;
        StatusText = "Checking for updates…";
        try
        {
            var update = await _checker.CheckAsync(_stop.Token);
            _settings.LastUpdateCheckUtc = DateTime.UtcNow;
            _settings.Save();
            Available = update;

            var checkedAt = DateTime.Now.ToString("t", CultureInfo.CurrentCulture);
            if (update is null)
            {
                ShowBanner = false;
                StatusText = $"ThermoForge is up to date (checked {checkedAt}).";
                return;
            }

            var skipped = _settings.SkippedUpdateVersion == update.Version.ToString(3);
            StatusText = skipped && !manual ? $"Version {update.Version.ToString(3)} skipped." : AvailableText;
            ShowBanner = manual || !skipped;
            if (ShowBanner && _notifiedVersion != update.Version)
            {
                _notifiedVersion = update.Version;
                UpdateFound?.Invoke(this, update);
            }
        }
        catch (UpdateException ex)
        {
            StatusText = $"Couldn't check for updates: {ex.Message}";
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand(CanExecute = nameof(CanInstall))]
    private async Task InstallAsync()
    {
        var update = Available!;
        if (!Installation.IsInstalledCopy(Environment.ProcessPath!))
        {
            var open = MessageBox.Show(
                $"This copy of ThermoForge wasn't installed with ThermoForge-Setup (it's the portable version or a development build), so it can't update itself.\n\nOpen the download page for {update.Version.ToString(3)}?",
                "Update ThermoForge", MessageBoxButton.YesNo, MessageBoxImage.Information);
            if (open == MessageBoxResult.Yes)
                OpenReleaseNotes();
            return;
        }

        var answer = MessageBox.Show(
            $"Install ThermoForge {update.Version.ToString(3)} now?\n\nThermoForge will close, update and reopen by itself. Windows will ask for permission to install.",
            "Update ThermoForge", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.Yes);
        if (answer != MessageBoxResult.Yes)
            return;

        IsBusy = true;
        IsDownloading = true;
        Progress = 0;
        try
        {
            var progress = new Progress<double>(p =>
            {
                Progress = p * 100;
                StatusText = $"Downloading ThermoForge {update.Version.ToString(3)}… {p:P0}";
            });
            var installer = await _checker.DownloadAsync(update, DownloadFolder, progress, _stop.Token);

            StatusText = "Starting the installer…";
            Process.Start(new ProcessStartInfo(installer, InstallerArguments) { UseShellExecute = true, Verb = "runas" });
            ExitForUpdate?.Invoke(this, EventArgs.Empty);
        }
        catch (UpdateException ex)
        {
            StatusText = ex.Message;
            MessageBox.Show(ex.Message, "Update failed", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == ErrorCancelled)
        {
            StatusText = "Update cancelled: Windows' permission prompt was dismissed.";
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            IsBusy = false;
            IsDownloading = false;
        }
    }

    private bool CanInstall() => Available is not null && !IsBusy;

    [RelayCommand(CanExecute = nameof(IsUpdateAvailable))]
    private void OpenReleaseNotes() =>
        Process.Start(new ProcessStartInfo((Available?.Page ?? UpdateChecker.ReleasesPage).ToString()) { UseShellExecute = true });

    [RelayCommand(CanExecute = nameof(IsUpdateAvailable))]
    private void SkipVersion()
    {
        _settings.SkippedUpdateVersion = Available!.Version.ToString(3);
        _settings.Save();
        ShowBanner = false;
        StatusText = $"Version {_settings.SkippedUpdateVersion} skipped. You'll be told about the next one.";
    }

    [RelayCommand]
    private void HideBanner() => ShowBanner = false;

    /// <summary>The previous update's installer can't delete itself while it runs; tidy up now.</summary>
    private static void CleanUpOldDownloads()
    {
        try
        {
            if (Directory.Exists(DownloadFolder))
                Directory.Delete(DownloadFolder, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static HttpClient CreateHttpClient()
    {
        // Long enough for the installer download on a slow connection.
        var http = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
        // GitHub's API rejects requests without a User-Agent.
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"ThermoForge/{UpdateChecker.CurrentVersion().ToString(3)}");
        return http;
    }
}
