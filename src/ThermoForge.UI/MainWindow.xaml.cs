using System.ComponentModel;
using System.Windows;
using ThermoForge.Core.Alerts;
using ThermoForge.Core.Processes;
using ThermoForge.UI.Services;
using ThermoForge.UI.ViewModels;

namespace ThermoForge.UI;

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel = new();
    private readonly TrayIcon _tray = new();
    private bool _exitRequested;
    private bool _monitorsStopped;

    public MainWindow()
    {
        InitializeComponent();
        FitToWorkArea();
        DataContext = _viewModel;
        Loaded += async (_, _) => await _viewModel.StartAsync();

        _tray.OpenRequested += (_, _) => ShowFromTray();
        _tray.ExitRequested += (_, _) => ExitApp();
        _tray.PauseToggled += (_, _) => _viewModel.Alerts.TogglePause();
        _viewModel.ExitRequested += (_, _) => ExitApp();
        _viewModel.NotificationRequested += (_, alert) => Notify(alert);
        _viewModel.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(MainViewModel.TrayStatus))
                _tray.SetStatus(_viewModel.TrayStatus);
            else if (e.PropertyName == nameof(MainViewModel.TrayText))
                _tray.SetText(_viewModel.TrayText);
        };
        _viewModel.Alerts.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(AlertsViewModel.IsPaused))
                _tray.SetPaused(_viewModel.Alerts.IsPaused);
        };
    }

    /// <summary>Laptops at 125–150 % scaling have less room than the default size; never open partly off-screen.</summary>
    private void FitToWorkArea()
    {
        var area = SystemParameters.WorkArea;
        Width = Math.Min(Width, area.Width - 40);
        Height = Math.Min(Height, area.Height - 40);
        MinWidth = Math.Min(MinWidth, Width);
        MinHeight = Math.Min(MinHeight, Height);
    }

    private void Notify(Alert alert)
    {
        Action open = alert.Pid is { } pid
            ? () => { ShowFromTray(); _viewModel.ShowProcess(pid); }
            : () => { ShowFromTray(); _viewModel.SelectedTab = MainViewModel.AlertsTab; };
        _tray.Notify(alert.Title, alert.Message, alert.Severity >= FindingSeverity.Medium, open);
    }

    private void ShowFromTray()
    {
        Show();
        if (WindowState == WindowState.Minimized)
            WindowState = WindowState.Normal;
        Activate();
    }

    private void ExitApp()
    {
        _exitRequested = true;
        Close();
    }

    protected override async void OnClosing(CancelEventArgs e)
    {
        if (!_exitRequested && _viewModel.Settings.CloseToTray)
        {
            // Keep monitoring in the background; the tray icon's Exit really quits.
            e.Cancel = true;
            Hide();
            if (!_viewModel.Settings.TrayHintShown)
            {
                _viewModel.Settings.TrayHintShown = true;
                _viewModel.Settings.Save();
                _tray.Notify("ThermoForge is still running",
                    "It keeps watching in the background. Right-click the tray icon to exit.", isWarning: false);
            }
            return;
        }

        if (_monitorsStopped)
        {
            base.OnClosing(e);
            return;
        }

        // Hold the close until the monitors have stopped and LibreHardwareMonitor has released its driver handles.
        e.Cancel = true;
        await _viewModel.DisposeAsync();
        _tray.Dispose();
        _monitorsStopped = true;
        Close();
    }
}
