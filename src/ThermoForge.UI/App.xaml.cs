using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace ThermoForge.UI;

public partial class App : Application
{
    public static string CrashLogPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ThermoForge", "crash.log");

    protected override void OnStartup(StartupEventArgs e)
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += (_, args) => LogCrash(args.ExceptionObject as Exception);
        TaskScheduler.UnobservedTaskException += (_, args) => LogCrash(args.Exception);
        base.OnStartup(e);
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
