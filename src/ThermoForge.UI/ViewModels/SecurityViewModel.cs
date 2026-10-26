using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using ThermoForge.Core.Models;
using ThermoForge.Core.Processes;
using ThermoForge.Core.Reports;
using ThermoForge.Core.Reputation;
using ThermoForge.Core.Services;
using ThermoForge.Core.Startup;
using ThermoForge.UI.Services;

namespace ThermoForge.UI.ViewModels;

/// <summary>
/// The Security tab: Microsoft Defender's status and history, the VirusTotal key and batch
/// checks, files checked so far, and report export.
/// </summary>
public sealed partial class SecurityViewModel : ObservableObject, IAsyncDisposable
{
    private static readonly TimeSpan DefenderInterval = TimeSpan.FromMinutes(1);

    /// <summary>Most files a batch check sends, so one click can't use up a day's quota.</summary>
    private const int MaxBatch = 25;

    /// <summary>VirusTotal results younger than this aren't fetched again by a batch check.</summary>
    private static readonly TimeSpan RecheckAfter = TimeSpan.FromDays(7);

    private const string VirusTotalSignupUrl = "https://www.virustotal.com/gui/join-us";

    private readonly FileChecker _checker;
    private readonly AlertsViewModel _alerts;
    private SynchronizationContext? _uiContext;
    private PollingLoop<DefenderReading>? _loop;
    private DefenderReading? _reading;
    private CancellationTokenSource? _batch;

    public SecurityViewModel(FileChecker checker, AlertsViewModel alerts)
    {
        _checker = checker;
        _alerts = alerts;
        _hasKey = checker.HasVirusTotalKey;
        RefreshFileChecks();
        checker.Store.Changed += (_, _) => Application.Current.Dispatcher.BeginInvoke(RefreshFileChecks);
    }

    public sealed record DefenderReading(DefenderStatus? Status, IReadOnlyList<DefenderDetection> Detections, DateTime Time);

    /// <param name="IsUnresolved">Recent, and Defender didn't remove or block it.</param>
    public sealed record DetectionRow(string TimeText, string Threat, string Severity, string Status, string Where, bool IsUnresolved);

    /// <param name="IsSerious">Detected strongly enough to count as Medium or High (not a lone engine).</param>
    public sealed record FileCheckRow(string Name, string Path, string Summary, bool IsDetected, bool IsSerious);

    public ObservableCollection<DetectionRow> Detections { get; } = new();
    public ObservableCollection<FileCheckRow> FileChecks { get; } = new();

    /// <summary>The latest data from the other tabs, for batch checks and reports.</summary>
    public ProcessSnapshot? LatestProcesses { get; set; }
    public StartupScan? LatestStartup { get; set; }
    public SensorSnapshot? LatestSensors { get; set; }

    /// <summary>Raised on the UI thread after each Defender read, for the alert engine.</summary>
    public event EventHandler<DefenderReading>? DefenderChecked;

    /// <summary>A batch check finished; startup entries should be rescanned to show the results.</summary>
    public event EventHandler? FilesChecked;

    [ObservableProperty]
    private string _defenderMode = "Reading Microsoft Defender…";

    [ObservableProperty]
    private string _realTimeText = "";

    [ObservableProperty]
    private string _signaturesText = "";

    [ObservableProperty]
    private string _problemText = "";

    [ObservableProperty]
    private string _detectionsText = "";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(KeyStatusText))]
    [NotifyCanExecuteChangedFor(nameof(RemoveKeyCommand), nameof(CheckFlaggedCommand))]
    private bool _hasKey;

    public string KeyStatusText => HasKey
        ? "API key saved, encrypted for your Windows account."
        : "No API key yet. Get a free one (sign up, then copy it from your profile's API key page) and paste it here.";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CheckFlaggedCommand), nameof(CancelCheckCommand))]
    private bool _isBatchRunning;

    [ObservableProperty]
    private string _batchStatus = "";

    [ObservableProperty]
    private string _exportStatus = "";

    /// <summary>Defender problems, unresolved detections and detected files; shown as a badge on the tab.</summary>
    [ObservableProperty]
    private int _alertCount;

    [ObservableProperty]
    private bool _hasHighRisk;

    public void Start()
    {
        _uiContext = SynchronizationContext.Current
            ?? throw new InvalidOperationException("Start must be called from the UI thread.");

        _loop = new PollingLoop<DefenderReading>(ReadDefender, DefenderInterval);
        _loop.Polled += (_, reading) => _uiContext.Post(_ => Apply(reading), null);
        _loop.Faulted += (_, ex) => _uiContext.Post(_ => DefenderMode = $"Could not read Defender: {ex.Message}", null);
        _loop.Start();
    }

    public async ValueTask DisposeAsync()
    {
        _batch?.Cancel();
        if (_loop is not null)
            await _loop.DisposeAsync();
    }

    private static DefenderReading ReadDefender() => new(Defender.ReadStatus(), Defender.ReadDetections(), DateTime.Now);

    [RelayCommand]
    private async Task RefreshDefenderAsync() => Apply(await Task.Run(ReadDefender));

    [RelayCommand]
    private static void OpenWindowsSecurity() =>
        Process.Start(new ProcessStartInfo("windowsdefender://threat") { UseShellExecute = true });

    [RelayCommand]
    private void SaveKey(string? key)
    {
        if (string.IsNullOrWhiteSpace(key))
            return;
        _checker.SetVirusTotalKey(key);
        HasKey = _checker.HasVirusTotalKey;
    }

    [RelayCommand(CanExecute = nameof(HasKey))]
    private void RemoveKey()
    {
        _checker.SetVirusTotalKey(null);
        HasKey = false;
    }

    [RelayCommand]
    private static void OpenVirusTotalSignup() =>
        Process.Start(new ProcessStartInfo(VirusTotalSignupUrl) { UseShellExecute = true });

    /// <summary>
    /// Looks up every flagged program and startup file not checked in the last week, one every
    /// 15 seconds (the free tier's pace). Only SHA-256 fingerprints are sent.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanCheckFlagged))]
    private async Task CheckFlaggedAsync()
    {
        var candidates = FlaggedFiles()
            .Where(path => _checker.Store.For(path)?.VirusTotal is not { } vt || DateTime.Now - vt.CheckedAt > RecheckAfter)
            .Take(MaxBatch)
            .ToList();
        if (candidates.Count == 0)
        {
            BatchStatus = "Nothing to check: every flagged file was checked in the last week.";
            return;
        }

        _batch = new CancellationTokenSource();
        IsBatchRunning = true;
        int checkedCount = 0, detected = 0;
        try
        {
            foreach (var path in candidates)
            {
                BatchStatus = $"Checking {checkedCount + 1} of {candidates.Count}: {Path.GetFileName(path)}… "
                    + "(VirusTotal's free tier allows 4 a minute)";
                try
                {
                    var result = await _checker.CheckVirusTotalAsync(path, _batch.Token);
                    checkedCount++;
                    if (result.VirusTotal!.Malicious > 0)
                        detected++;
                }
                catch (IOException)
                {
                    checkedCount++; // Gone or unreadable; nothing to look up.
                }
            }
            BatchStatus = $"Checked {checkedCount} files: " + (detected == 0 ? "no detections." : $"{detected} detected by antivirus engines.");
        }
        catch (VirusTotalException ex)
        {
            BatchStatus = $"Stopped after {checkedCount} files: {ex.Message}";
        }
        catch (OperationCanceledException)
        {
            BatchStatus = $"Cancelled after {checkedCount} files.";
        }
        finally
        {
            IsBatchRunning = false;
            _batch.Dispose();
            _batch = null;
            if (checkedCount > 0)
                FilesChecked?.Invoke(this, EventArgs.Empty);
        }
    }

    private bool CanCheckFlagged() => HasKey && !IsBatchRunning;

    [RelayCommand(CanExecute = nameof(IsBatchRunning))]
    private void CancelCheck() => _batch?.Cancel();

    private IEnumerable<string> FlaggedFiles()
    {
        var processes = (LatestProcesses?.Processes ?? [])
            .Where(p => p.Severity > FindingSeverity.None && p.File is not null)
            .OrderByDescending(p => p.Risk)
            .Select(p => p.Process.Path!);
        var startup = (LatestStartup?.Entries ?? [])
            .Where(e => e.Severity > FindingSeverity.None && e.File is not null)
            .OrderByDescending(e => e.Risk)
            .Select(e => e.ImagePath!);
        return processes.Concat(startup).Distinct(StringComparer.OrdinalIgnoreCase);
    }

    [RelayCommand]
    private void ExportHtml() => Export("HTML report (*.html)|*.html", ".html", report => HtmlReport.Render(report), open: true);

    [RelayCommand]
    private void ExportJson() => Export("JSON (*.json)|*.json", ".json", report => report.ToJson(), open: false);

    private void Export(string filter, string extension, Func<SecurityReport, string> render, bool open)
    {
        var dialog = new SaveFileDialog
        {
            Filter = filter,
            DefaultExt = extension,
            FileName = $"ThermoForge report {Environment.MachineName} {DateTime.Now:yyyy-MM-dd HHmm}{extension}",
        };
        if (dialog.ShowDialog() != true)
            return;

        var report = ReportBuilder.Build(
            new ReportInputs(LatestProcesses, LatestStartup, LatestSensors, _reading?.Status, _reading?.Detections ?? [],
                _checker.Store.All, _alerts.Alerts.ToList()),
            DateTime.Now,
            TemperatureThresholds.Default);
        try
        {
            File.WriteAllText(dialog.FileName, render(report));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show(ex.Message, "Could not save the report", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        ExportStatus = $"Saved {Path.GetFileName(dialog.FileName)}";
        if (open)
            Process.Start(new ProcessStartInfo(dialog.FileName) { UseShellExecute = true });
    }

    private void Apply(DefenderReading reading)
    {
        _reading = reading;
        var status = reading.Status;
        var problem = status?.Problem(reading.Time);
        DefenderMode = status switch
        {
            null => "Microsoft Defender's status isn't available (another antivirus may have replaced it).",
            { IsActive: false } => $"Standing by ({status.RunningMode}): another antivirus is protecting this PC.",
            _ => $"Microsoft Defender is your active antivirus (version {status.Version ?? "unknown"}).",
        };
        RealTimeText = status is null ? "" : $"Real-time protection: {(status.RealTimeProtection ? "on" : "OFF")}";
        SignaturesText = status?.SignaturesUpdated is { } updated
            ? $"Virus definitions updated {updated.ToString("g", CultureInfo.CurrentCulture)}"
            : "";
        ProblemText = problem ?? "";

        Detections.Clear();
        foreach (var d in reading.Detections)
        {
            var unresolved = d.IsUnresolved && d.Time > reading.Time - ReportBuilder.RecentDetection;
            Detections.Add(new DetectionRow(d.Time.ToString("g", CultureInfo.CurrentCulture), d.Threat, d.Severity, d.Status,
                string.Join(Environment.NewLine, d.Resources.DefaultIfEmpty(d.ProcessName ?? "")), unresolved));
        }
        DetectionsText = reading.Detections.Count == 0
            ? "Defender's history has no detections."
            : $"{reading.Detections.Count} detections in Defender's history (Windows keeps it for a limited time).";

        UpdateCounts();
        DefenderChecked?.Invoke(this, reading);
    }

    private void RefreshFileChecks()
    {
        FileChecks.Clear();
        foreach (var f in _checker.Store.All.OrderByDescending(f => f.VirusTotal?.CheckedAt ?? f.Defender?.ScannedAt))
        {
            var detected = (f.VirusTotal?.Malicious ?? 0) > 0 || f.Defender?.Threat is not null;
            FileChecks.Add(new FileCheckRow(Path.GetFileName(f.Path), f.Path, f.Summary, detected,
                f.Findings().Any(x => x.Severity >= FindingSeverity.Medium)));
        }
        UpdateCounts();
    }

    private void UpdateCounts()
    {
        var weakened = _reading?.Status is { } s && s.IsActive && (!s.AntivirusEnabled || !s.RealTimeProtection);
        var unresolved = Detections.Count(d => d.IsUnresolved);
        var detectedFiles = FileChecks.Count(f => f.IsSerious);
        AlertCount = (ProblemText.Length > 0 ? 1 : 0) + unresolved + detectedFiles;
        HasHighRisk = weakened || unresolved > 0 || detectedFiles > 0;
    }
}
