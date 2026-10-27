using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ThermoForge.Core.Alerts;
using ThermoForge.Core.Platform;
using ThermoForge.Core.Processes;
using ThermoForge.UI.Services;

namespace ThermoForge.UI.ViewModels;

/// <summary>The Alerts tab: alert history, notification preferences and the trusted-programs list.</summary>
public sealed partial class AlertsViewModel : ObservableObject
{
    private const int MaxAlerts = 200;
    private const int ErrorCancelled = 1223;
    private static readonly TimeSpan PauseLength = TimeSpan.FromHours(1);

    private readonly AppSettings _settings;
    private readonly TrustStore _trust;

    public AlertsViewModel(AppSettings settings, TrustStore trust)
    {
        _settings = settings;
        _trust = trust;
        _notifyProcesses = settings.NotifyProcesses;
        _notifyTemperature = settings.NotifyTemperature;
        _notifyStartup = settings.NotifyStartup;
        _notifySecurity = settings.NotifySecurity;
        _closeToTray = settings.CloseToTray;
        RefreshTrusted();
        trust.Changed += (_, _) => Application.Current.Dispatcher.Invoke(RefreshTrusted);
    }

    /// <summary>Newest first.</summary>
    public ObservableCollection<Alert> Alerts { get; } = new();

    public ObservableCollection<TrustedProgram> TrustedPrograms { get; } = new();

    [ObservableProperty]
    private bool _notifyProcesses;

    [ObservableProperty]
    private bool _notifyTemperature;

    [ObservableProperty]
    private bool _notifyStartup;

    [ObservableProperty]
    private bool _notifySecurity;

    [ObservableProperty]
    private bool _closeToTray;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsPaused), nameof(PauseText))]
    private DateTime? _pausedUntil;

    public bool IsPaused => PausedUntil > DateTime.Now;

    public string PauseText => IsPaused
        ? $"Notifications paused until {PausedUntil:t}"
        : "Notifications are on";

    [ObservableProperty]
    private AutoStartState _autoStart;

    [ObservableProperty]
    private bool _isChangingAutoStart;

    public string AutoStartText => AutoStart switch
    {
        AutoStartState.On => "On: ThermoForge starts in the tray when you sign in, with administrator rights and no UAC prompt.",
        AutoStartState.OnOtherPath => "On, but for a ThermoForge in another folder. Turn it on again to use this copy.",
        _ => "Off: ThermoForge only runs when you open it.",
    };

    public string AutoStartButtonText => AutoStart switch
    {
        AutoStartState.On => "Don't start with Windows",
        AutoStartState.OnOtherPath => "Use this copy",
        _ => "Start with Windows",
    };

    partial void OnAutoStartChanged(AutoStartState value)
    {
        OnPropertyChanged(nameof(AutoStartText));
        OnPropertyChanged(nameof(AutoStartButtonText));
    }

    public async Task RefreshAutoStartAsync() =>
        AutoStart = await Task.Run(() => Core.Platform.AutoStart.Query(Environment.ProcessPath!));

    /// <summary>
    /// The logon task needs admin rights to create or remove, so an unelevated ThermoForge runs
    /// an elevated copy of itself with <c>--autostart on|off</c> (one UAC prompt).
    /// </summary>
    [RelayCommand]
    private async Task ToggleAutoStartAsync()
    {
        var enable = AutoStart != AutoStartState.On;
        IsChangingAutoStart = true;
        try
        {
            if (SystemEnvironment.IsAdministrator())
            {
                await Task.Run(() =>
                {
                    if (enable)
                        Core.Platform.AutoStart.Enable(Environment.ProcessPath!);
                    else
                        Core.Platform.AutoStart.Disable();
                });
            }
            else
            {
                using var helper = Process.Start(new ProcessStartInfo(Environment.ProcessPath!, $"{App.AutoStartArgument} {(enable ? "on" : "off")}")
                {
                    UseShellExecute = true,
                    Verb = "runas",
                })!;
                await helper.WaitForExitAsync();
                if (helper.ExitCode != 0)
                    throw new InvalidOperationException($"Windows refused the change. Details are in {App.CrashLogPath}.");
            }
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == ErrorCancelled)
        {
            // UAC prompt dismissed.
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            MessageBox.Show(ex.Message, "Could not change \"Start with Windows\"", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            IsChangingAutoStart = false;
        }
        await RefreshAutoStartAsync();
    }

    public void Add(Alert alert)
    {
        Alerts.Insert(0, alert);
        while (Alerts.Count > MaxAlerts)
            Alerts.RemoveAt(Alerts.Count - 1);
    }

    /// <summary>Whether this alert should also pop up, not just be listed here.</summary>
    public bool ShouldNotify(Alert alert)
    {
        if (IsPaused)
            return false;
        if (PausedUntil is not null)
            PausedUntil = null; // Pause ran out.

        return alert.Kind switch
        {
            AlertKind.Process => NotifyProcesses,
            AlertKind.Temperature => NotifyTemperature,
            AlertKind.Startup => NotifyStartup,
            AlertKind.Security => NotifySecurity,
            _ => true,
        };
    }

    [RelayCommand]
    public void TogglePause() => PausedUntil = IsPaused ? null : DateTime.Now + PauseLength;

    [RelayCommand]
    private void Clear() => Alerts.Clear();

    [RelayCommand]
    private void RemoveTrust(TrustedProgram program) => _trust.Remove(program.Path);

    partial void OnNotifyProcessesChanged(bool value) => Save(s => s.NotifyProcesses = value);

    partial void OnNotifyTemperatureChanged(bool value) => Save(s => s.NotifyTemperature = value);

    partial void OnNotifyStartupChanged(bool value) => Save(s => s.NotifyStartup = value);

    partial void OnNotifySecurityChanged(bool value) => Save(s => s.NotifySecurity = value);

    partial void OnCloseToTrayChanged(bool value) => Save(s => s.CloseToTray = value);

    private void Save(Action<AppSettings> change)
    {
        change(_settings);
        _settings.Save();
    }

    private void RefreshTrusted()
    {
        TrustedPrograms.Clear();
        foreach (var program in _trust.Programs)
            TrustedPrograms.Add(program);
    }
}
