using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ThermoForge.Core.Processes;
using ThermoForge.Core.Services;
using ThermoForge.Core.Startup;

namespace ThermoForge.UI.ViewModels;

/// <summary>The Startup tab: everything set to run automatically, rescanned every few minutes.</summary>
public sealed partial class StartupViewModel : ObservableObject, IAsyncDisposable
{
    private static readonly TimeSpan ScanInterval = TimeSpan.FromMinutes(5);

    private readonly Dictionary<string, StartupRowViewModel> _rows = new();
    private readonly TrustStore _trust;
    private readonly SemaphoreSlim _scanLock = new(1, 1);
    private SynchronizationContext? _uiContext;
    private StartupScanner? _scanner;
    private PollingLoop<StartupScan?>? _loop;

    public StartupViewModel(TrustStore trust)
    {
        _trust = trust;
        EntriesView = new ListCollectionView(Entries)
        {
            Filter = Matches,
            IsLiveSorting = true,
        };
        EntriesView.SortDescriptions.Add(new SortDescription(nameof(StartupRowViewModel.Risk), ListSortDirection.Descending));
        EntriesView.SortDescriptions.Add(new SortDescription(nameof(StartupRowViewModel.IsNew), ListSortDirection.Descending));
        EntriesView.SortDescriptions.Add(new SortDescription(nameof(StartupRowViewModel.Kind), ListSortDirection.Ascending));
        EntriesView.SortDescriptions.Add(new SortDescription(nameof(StartupRowViewModel.Name), ListSortDirection.Ascending));
    }

    public ObservableCollection<StartupRowViewModel> Entries { get; } = new();
    public ListCollectionView EntriesView { get; }

    /// <summary>Raised on the UI thread after each scan has been applied.</summary>
    public event EventHandler<StartupScan>? ScanApplied;

    [ObservableProperty]
    private string _searchText = "";

    [ObservableProperty]
    private bool _showFlaggedOnly;

    [ObservableProperty]
    private bool _hideMicrosoft = true;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ToggleEnabledCommand), nameof(OpenFileLocationCommand),
        nameof(CopyCommandCommand), nameof(SearchOnlineCommand), nameof(ToggleTrustCommand))]
    private StartupRowViewModel? _selectedEntry;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(RescanCommand))]
    private bool _isScanning;

    [ObservableProperty]
    private string _statusText = "Scanning startup entries…";

    /// <summary>Entries with Medium or High risk; shown as a badge on the tab.</summary>
    [ObservableProperty]
    private int _alertCount;

    public bool HasHighRisk => Entries.Any(r => r.Severity == FindingSeverity.High);

    public void Start()
    {
        _uiContext = SynchronizationContext.Current
            ?? throw new InvalidOperationException("Start must be called from the UI thread.");

        _scanner = StartupScanner.ForCurrentSystem(_trust);
        _loop = new PollingLoop<StartupScan?>(() => ScanOnce(), ScanInterval);
        _loop.Polled += (_, scan) =>
        {
            if (scan is not null)
                _uiContext.Post(_ => Apply(scan), null);
        };
        _loop.Faulted += (_, ex) => _uiContext.Post(_ => StatusText = $"Startup scan failed: {ex.Message}", null);
        _loop.Start();
    }

    public async ValueTask DisposeAsync()
    {
        if (_loop is not null)
            await _loop.DisposeAsync();
    }

    partial void OnSearchTextChanged(string value) => EntriesView.Refresh();

    partial void OnShowFlaggedOnlyChanged(bool value) => EntriesView.Refresh();

    partial void OnHideMicrosoftChanged(bool value) => EntriesView.Refresh();

    [RelayCommand(CanExecute = nameof(CanRescan))]
    private async Task RescanAsync()
    {
        var scan = await Task.Run(() => ScanOnce());
        if (scan is not null)
            Apply(scan);
    }

    private bool CanRescan() => !IsScanning;

    /// <summary>Runs one scan unless one is already running (timer and button can overlap).</summary>
    private StartupScan? ScanOnce()
    {
        if (_scanner is null || !_scanLock.Wait(0))
            return null;
        try
        {
            _uiContext?.Post(_ => IsScanning = true, null);
            return _scanner.Scan();
        }
        finally
        {
            _uiContext?.Post(_ => IsScanning = false, null);
            _scanLock.Release();
        }
    }

    [RelayCommand(CanExecute = nameof(CanToggle))]
    private async Task ToggleEnabledAsync()
    {
        var row = SelectedEntry!;
        var enable = !row.Raw.Enabled;
        if (!enable)
        {
            var answer = MessageBox.Show(
                $"Turn off {row.Name}?\n\nIt won't start automatically any more. Nothing is deleted; you can turn it back on here or in Task Manager / Task Scheduler.",
                "Turn off startup entry", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No);
            if (answer != MessageBoxResult.Yes)
                return;
        }

        try
        {
            StartupControl.SetEnabled(row.Raw, enable);
        }
        catch (InvalidOperationException ex)
        {
            MessageBox.Show(ex.Message, "Could not change startup entry", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        await RescanAsync();
    }

    private bool CanToggle() => SelectedEntry is { CanToggle: true };

    [RelayCommand(CanExecute = nameof(HasPath))]
    private void OpenFileLocation() =>
        Process.Start("explorer.exe", $"/select,\"{SelectedEntry!.Path}\"");

    private bool HasPath() => SelectedEntry?.Path is not null;

    [RelayCommand(CanExecute = nameof(HasSelection))]
    private void CopyCommand()
    {
        try
        {
            Clipboard.SetText(SelectedEntry!.CommandText);
        }
        catch (COMException)
        {
            // Another app is holding the clipboard.
        }
    }

    [RelayCommand(CanExecute = nameof(HasSelection))]
    private void SearchOnline()
    {
        var subject = SelectedEntry!.Path is { } path ? System.IO.Path.GetFileName(path) : SelectedEntry.Name;
        var query = Uri.EscapeDataString($"\"{subject}\" startup");
        Process.Start(new ProcessStartInfo($"https://www.google.com/search?q={query}") { UseShellExecute = true });
    }

    private bool HasSelection() => SelectedEntry is not null;

    [RelayCommand(CanExecute = nameof(HasPath))]
    private async Task ToggleTrustAsync()
    {
        var row = SelectedEntry!;
        if (row.IsTrusted)
        {
            _trust.Remove(row.Path!);
        }
        else
        {
            var answer = MessageBox.Show(
                $"Trust {System.IO.Path.GetFileName(row.Path)}?\n\n{row.Path}\n\nIts findings will no longer count, here and on the Processes tab. "
                + "If the file is ever replaced or modified, ThermoForge will check it again.",
                "Trust program", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No);
            if (answer != MessageBoxResult.Yes)
                return;
            try
            {
                _trust.Trust(row.Path!, System.IO.Path.GetFileName(row.Path!), string.IsNullOrEmpty(row.Publisher) ? null : row.Publisher);
            }
            catch (IOException ex)
            {
                MessageBox.Show(ex.Message, "Could not trust program", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
        }
        await RescanAsync();
    }

    private bool Matches(object item)
    {
        var row = (StartupRowViewModel)item;
        if (ShowFlaggedOnly && !row.IsFlagged)
            return false;
        if (HideMicrosoft && row.IsMicrosoft)
            return false;
        if (string.IsNullOrWhiteSpace(SearchText))
            return true;

        var term = SearchText.Trim();
        return row.Name.Contains(term, StringComparison.OrdinalIgnoreCase)
            || row.CommandText.Contains(term, StringComparison.OrdinalIgnoreCase)
            || row.Publisher.Contains(term, StringComparison.OrdinalIgnoreCase)
            || row.Kind.Contains(term, StringComparison.OrdinalIgnoreCase)
            || row.Description.Contains(term, StringComparison.OrdinalIgnoreCase);
    }

    private void Apply(StartupScan scan)
    {
        var selectedId = SelectedEntry?.Raw.Id;
        var alive = new HashSet<string>();
        foreach (var entry in scan.Entries)
        {
            if (!alive.Add(entry.Raw.Id))
                continue; // The same command listed twice (e.g. a task with two identical actions).

            if (_rows.TryGetValue(entry.Raw.Id, out var row))
            {
                row.Update(entry);
            }
            else
            {
                row = new StartupRowViewModel(entry);
                _rows.Add(entry.Raw.Id, row);
                Entries.Add(row);
            }
        }

        foreach (var (id, row) in _rows.Where(r => !alive.Contains(r.Key)).ToList())
        {
            _rows.Remove(id);
            Entries.Remove(row);
        }

        // Re-evaluate filters (Microsoft / flagged) and the details pane after the refresh.
        EntriesView.Refresh();
        if (selectedId is not null && _rows.TryGetValue(selectedId, out var selected))
            SelectedEntry = selected;
        else if (selectedId is not null)
            SelectedEntry = null;
        ToggleEnabledCommand.NotifyCanExecuteChanged();

        AlertCount = Entries.Count(r => r.Severity >= FindingSeverity.Medium);
        var hidden = Entries.Count(r => r.IsMicrosoft);
        var isNew = Entries.Count(r => r.IsNew);
        StatusText = $"Scanned {scan.Timestamp:T} · {Entries.Count} entries · {Entries.Count(r => r.IsFlagged)} flagged"
            + (isNew > 0 ? $" · {isNew} new" : "")
            + (HideMicrosoft && hidden > 0 ? $" · {hidden} clean Microsoft entries hidden" : "")
            + (scan.Errors.Count > 0 ? $" · {string.Join("; ", scan.Errors)}" : "");

        ScanApplied?.Invoke(this, scan);
    }
}
