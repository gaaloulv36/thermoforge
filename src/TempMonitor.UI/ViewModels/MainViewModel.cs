using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TempMonitor.Core.Platform;

namespace TempMonitor.UI.ViewModels;

/// <summary>Window-level state: the tabs plus elevation/driver warnings that affect all of them.</summary>
public sealed partial class MainViewModel : ObservableObject, IAsyncDisposable
{
    private const int ErrorCancelled = 1223;

    public HardwareViewModel Hardware { get; } = new();
    public ProcessesViewModel Processes { get; } = new();

    public bool ShowAdminWarning { get; } = !SystemEnvironment.IsAdministrator();
    public bool ShowPawnIoWarning { get; } = !SystemEnvironment.IsPawnIoInstalled();

    public async Task StartAsync()
    {
        Processes.Start();
        await Hardware.StartAsync();
    }

    public async ValueTask DisposeAsync()
    {
        await Processes.DisposeAsync();
        await Hardware.DisposeAsync();
    }

    [RelayCommand]
    private static void RestartAsAdministrator()
    {
        var startInfo = new ProcessStartInfo(Environment.ProcessPath!)
        {
            UseShellExecute = true,
            Verb = "runas",
        };

        try
        {
            Process.Start(startInfo);
            // Close (not Shutdown) so the window's closing handler can release the sensors first.
            Application.Current.MainWindow?.Close();
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == ErrorCancelled)
        {
            // User dismissed the UAC prompt; keep running unelevated.
        }
    }

    [RelayCommand]
    private static void OpenPawnIoDownload() =>
        Process.Start(new ProcessStartInfo(SystemEnvironment.PawnIoDownloadUrl) { UseShellExecute = true });
}
