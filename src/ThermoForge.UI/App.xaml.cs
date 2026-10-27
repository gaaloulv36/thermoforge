using System.IO;
using System.Windows;
using System.Windows.Threading;
using ThermoForge.Core.Platform;
using ThermoForge.UI.Services;

namespace ThermoForge.UI;

public partial class App : Application
{
    /// <summary>Command-line switch for the elevated helper that changes "Start with Windows".</summary>
    public const string AutoStartArgument = "--autostart";

    /// <summary>Command-line switch passed by "Restart as administrator".</summary>
    public const string RestartedArgument = "--restarted";

    private readonly SingleInstance _instance = new();

    public static string CrashLogPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ThermoForge", "crash.log");

    protected override void OnStartup(StartupEventArgs e)
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += (_, args) => LogCrash(args.ExceptionObject as Exception);
        TaskScheduler.UnobservedTaskException += (_, args) => LogCrash(args.Exception);
        base.OnStartup(e);

        var args = e.Args.Select(a => a.ToLowerInvariant()).ToList();
        if (args.IndexOf(AutoStartArgument) is >= 0 and var index)
        {
            // Elevated helper run by the "Start with Windows" switch or the installer; no window.
            Shutdown(ChangeAutoStart(args.ElementAtOrDefault(index + 1)));
            return;
        }

        // A copy restarting as administrator waits for the old one to close.
        var wait = args.Contains(RestartedArgument) ? TimeSpan.FromSeconds(15) : TimeSpan.Zero;
        if (!_instance.TryAcquire(wait))
        {
            SingleInstance.SignalFirstInstance();
            Shutdown();
            return;
        }

        var window = new MainWindow();
        MainWindow = window;
        if (args.Contains(AutoStart.TrayArgument))
            window.StartInTray();
        else
            window.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _instance.Dispose();
        base.OnExit(e);
    }

    /// <summary>
    /// <c>--autostart on|off</c>: turns the logon task on or off for the current user. Needs admin
    /// rights; exit code 0 on success.
    /// </summary>
    private static int ChangeAutoStart(string? value)
    {
        try
        {
            if (value == "off")
                AutoStart.Disable();
            else
                AutoStart.Enable(Environment.ProcessPath!);
            return 0;
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            LogCrash(ex);
            return 1;
        }
    }

    private static void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        LogCrash(e.Exception);
        MessageBox.Show($"Unexpected error:\n\n{e.Exception.Message}\n\nDetails were written to:\n{CrashLogPath}",
            "ThermoForge", MessageBoxButton.OK, MessageBoxImage.Error);
    }

    private static void LogCrash(Exception? ex)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(CrashLogPath)!);
            File.AppendAllText(CrashLogPath, $"[{DateTime.Now:O}] {ex}{Environment.NewLine}{Environment.NewLine}");
        }
        catch (IOException)
        {
            // Nothing sensible left to do if the log itself cannot be written.
        }
    }
}
