using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ThermoForge.Core.Alerts;
using ThermoForge.Core.Models;
using ThermoForge.Core.Platform;
using ThermoForge.Core.Processes;
using ThermoForge.Core.Services;
using ThermoForge.Core.Startup;
using ThermoForge.UI.Services;

namespace ThermoForge.UI.ViewModels;

/// <summary>
/// Window-level state: the tabs, elevation/driver warnings, and the alert pipeline that
/// turns process and sensor snapshots into alerts and an overall tray status.
/// </summary>
public sealed partial class MainViewModel : ObservableObject, IAsyncDisposable
{
    private const int ErrorCancelled = 1223;

    public const int HardwareTab = 0;
    public const int ProcessesTab = 1;
    public const int NetworkTab = 2;
    public const int StartupTab = 3;
    public const int AlertsTab = 4;

    private readonly AlertEngine _alertEngine = new(TemperatureThresholds.Default);
    private bool _startupSummaryDone;

    public MainViewModel()
    {
        Settings = AppSettings.Load();
        var trust = new TrustStore(TrustStore.DefaultPath);
        Processes = new ProcessesViewModel(trust);
        Startup = new StartupViewModel(trust);
        Alerts = new AlertsViewModel(Settings, trust);

        Processes.SnapshotApplied += (_, snapshot) =>
        {
            Network.Apply(snapshot);
            OnProcessSnapshot(snapshot);
        };
        Network.ProcessRequested += (_, pid) => ShowProcess(pid);
        Hardware.SnapshotApplied += (_, snapshot) => OnSensorSnapshot(snapshot);
        Startup.ScanApplied += (_, scan) => OnStartupScan(scan);
    }

    public AppSettings Settings { get; }
    public HardwareViewModel Hardware { get; } = new();
    public ProcessesViewModel Processes { get; }
    public NetworkViewModel Network { get; } = new();
    public StartupViewModel Startup { get; }
    public AlertsViewModel Alerts { get; }

    public bool ShowAdminWarning { get; } = !SystemEnvironment.IsAdministrator();
    public bool ShowPawnIoWarning { get; } = !SystemEnvironment.IsPawnIoInstalled();

    [ObservableProperty]
    private int _selectedTab;

    [ObservableProperty]
    private TrayStatus _trayStatus;

    [ObservableProperty]
    private string _trayText = "ThermoForge · starting…";

    /// <summary>A new alert that should pop up (already filtered by the user's notification settings).</summary>
    public event EventHandler<Alert>? NotificationRequested;

    /// <summary>The app should exit for real (not hide to the tray).</summary>
    public event EventHandler? ExitRequested;

    public async Task StartAsync()
    {
        Processes.Start();
        Startup.Start();
        await Hardware.StartAsync();
    }

    public async ValueTask DisposeAsync()
    {
        await Processes.DisposeAsync();
        await Startup.DisposeAsync();
        await Hardware.DisposeAsync();
    }

    /// <summary>Brings the Processes tab up with the given process selected.</summary>
    public void ShowProcess(int pid)
    {
        SelectedTab = ProcessesTab;
        Processes.Select(pid);
    }

    [RelayCommand]
    private void RestartAsAdministrator()
    {
        var startInfo = new ProcessStartInfo(Environment.ProcessPath!)
        {
            UseShellExecute = true,
            Verb = "runas",
        };

        try
        {
            Process.Start(startInfo);
            // Exit (not hide to tray) so the window's closing handler releases the sensors first.
            ExitRequested?.Invoke(this, EventArgs.Empty);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == ErrorCancelled)
        {
            // User dismissed the UAC prompt; keep running unelevated.
        }
    }

    [RelayCommand]
    private static void OpenPawnIoDownload() =>
        Process.Start(new ProcessStartInfo(SystemEnvironment.PawnIoDownloadUrl) { UseShellExecute = true });

    private void OnProcessSnapshot(ProcessSnapshot snapshot)
    {
        if (!_startupSummaryDone)
        {
            // Risky processes that were already running are listed once, without popping up:
            // the window is open and showing them anyway.
            _startupSummaryDone = true;
            foreach (var alert in AlertEngine.StartupSummary(snapshot, _alertEngine.MinimumProcessSeverity))
                Alerts.Add(alert);
        }

        Raise(_alertEngine.Evaluate(snapshot));
        UpdateTray();
    }

    private void OnSensorSnapshot(SensorSnapshot snapshot)
    {
        Raise(_alertEngine.Evaluate(snapshot));
        UpdateTray();
    }

    private void OnStartupScan(StartupScan scan)
    {
        Raise(_alertEngine.Evaluate(scan));
        UpdateTray();
    }

    private void Raise(IReadOnlyList<Alert> alerts)
    {
        foreach (var alert in alerts)
        {
            Alerts.Add(alert);
            if (Alerts.ShouldNotify(alert))
                NotificationRequested?.Invoke(this, alert);
        }
    }

    private void UpdateTray()
    {
        var temperature = Hardware.WorstStatus;
        TrayStatus = Processes.HasHighRisk || Startup.HasHighRisk || temperature == TemperatureStatus.Hot ? TrayStatus.Alert
            : Processes.AlertCount > 0 || Startup.AlertCount > 0 || temperature == TemperatureStatus.Warm ? TrayStatus.Warning
            : TrayStatus.Normal;

        var risky = (Processes.AlertCount + Startup.AlertCount) switch
        {
            0 => "nothing risky",
            1 => "1 risky item",
            var n => $"{n} risky items",
        };
        TrayText = $"ThermoForge\nCPU {Hardware.CpuTemperature.Value} · {risky}"
                   + (Alerts.IsPaused ? "\nNotifications paused" : "");
    }
}
