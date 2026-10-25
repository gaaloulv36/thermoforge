using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TempMonitor.Core.Processes;
using TempMonitor.Core.Services;

namespace TempMonitor.UI.ViewModels;

public sealed partial class ProcessesViewModel : ObservableObject, IAsyncDisposable
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(3);

    private readonly Dictionary<(int Pid, DateTime? Started), ProcessRowViewModel> _rows = new();
    private SynchronizationContext? _uiContext;
    private ProcessMonitor? _monitor;
    private PollingLoop<ProcessSnapshot>? _loop;

    public ProcessesViewModel()
    {
        ProcessesView = new ListCollectionView(Processes)
        {
            Filter = Matches,
            IsLiveSorting = true,
            IsLiveFiltering = true,
        };
        // Most suspicious first, then busiest. Live sorting re-sorts on these properties as they change.
        ProcessesView.SortDescriptions.Add(new SortDescription(nameof(ProcessRowViewModel.Severity), ListSortDirection.Descending));
        ProcessesView.SortDescriptions.Add(new SortDescription(nameof(ProcessRowViewModel.CpuPercent), ListSortDirection.Descending));
        ProcessesView.LiveFilteringProperties.Add(nameof(ProcessRowViewModel.Severity));
    }

    public ObservableCollection<ProcessRowViewModel> Processes { get; } = new();
    public ListCollectionView ProcessesView { get; }

    [ObservableProperty]
    private string _searchText = "";

    [ObservableProperty]
    private bool _showFlaggedOnly;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(EndProcessCommand), nameof(OpenFileLocationCommand),
        nameof(CopyPathCommand), nameof(SearchOnlineCommand))]
    private ProcessRowViewModel? _selectedProcess;

    [ObservableProperty]
    private string _statusText = "Scanning processes…";

    /// <summary>Processes with a Medium or High finding; shown as a badge on the tab.</summary>
    [ObservableProperty]
    private int _alertCount;

    public void Start()
    {
        _uiContext = SynchronizationContext.Current
            ?? throw new InvalidOperationException("Start must be called from the UI thread.");

        _monitor = new ProcessMonitor(ProcessAnalyzer.ForCurrentSystem());
        _loop = new PollingLoop<ProcessSnapshot>(_monitor.Poll, PollInterval);
        _loop.Polled += (_, snapshot) => _uiContext.Post(_ => Apply(snapshot), null);
        _loop.Faulted += (_, ex) => _uiContext.Post(_ => StatusText = $"Process scan failed: {ex.Message}", null);
        _loop.Start();
    }

    public async ValueTask DisposeAsync()
    {
        if (_loop is not null)
            await _loop.DisposeAsync();
        _monitor?.Dispose();
    }

    partial void OnSearchTextChanged(string value) => ProcessesView.Refresh();

    partial void OnShowFlaggedOnlyChanged(bool value) => ProcessesView.Refresh();

    [RelayCommand(CanExecute = nameof(CanEndProcess))]
    private void EndProcess()
    {
        var row = SelectedProcess!;
        var answer = MessageBox.Show(
            $"End {row.Name} (PID {row.Pid})?\n\nAny unsaved work in it will be lost.",
            "End process", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes)
            return;

        try
        {
            ProcessControl.Kill(row.Raw);
        }
        catch (InvalidOperationException ex)
        {
            MessageBox.Show(ex.Message, "Could not end process", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private bool CanEndProcess() => SelectedProcess is { IsCritical: false };

    [RelayCommand(CanExecute = nameof(HasPath))]
    private void OpenFileLocation() =>
        Process.Start("explorer.exe", $"/select,\"{SelectedProcess!.Path}\"");

    [RelayCommand(CanExecute = nameof(HasPath))]
    private void CopyPath()
    {
        try
        {
            Clipboard.SetText(SelectedProcess!.Path!);
        }
        catch (COMException)
        {
            // Another app is holding the clipboard; nothing useful to do.
        }
    }

    private bool HasPath() => SelectedProcess?.Path is not null;

    [RelayCommand(CanExecute = nameof(HasSelection))]
    private void SearchOnline()
    {
        var query = Uri.EscapeDataString($"\"{SelectedProcess!.Name}\" process");
        Process.Start(new ProcessStartInfo($"https://www.google.com/search?q={query}") { UseShellExecute = true });
    }

    private bool HasSelection() => SelectedProcess is not null;

    private bool Matches(object item)
    {
        var row = (ProcessRowViewModel)item;
        if (ShowFlaggedOnly && !row.IsFlagged)
            return false;
        if (string.IsNullOrWhiteSpace(SearchText))
            return true;

        var term = SearchText.Trim();
        return row.Name.Contains(term, StringComparison.OrdinalIgnoreCase)
            || row.Pid.ToString().Equals(term, StringComparison.Ordinal)
            || (row.Path?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false)
            || row.Publisher.Contains(term, StringComparison.OrdinalIgnoreCase)
            || row.Description.Contains(term, StringComparison.OrdinalIgnoreCase);
    }

    private void Apply(ProcessSnapshot snapshot)
    {
        var alive = new HashSet<(int, DateTime?)>();
        foreach (var info in snapshot.Processes)
        {
            var key = (info.Process.Pid, info.Process.StartTime);
            alive.Add(key);
            if (_rows.TryGetValue(key, out var row))
            {
                row.Update(info);
            }
            else
            {
                row = new ProcessRowViewModel(info);
                _rows.Add(key, row);
                Processes.Add(row);
            }
        }

        foreach (var (key, row) in _rows.Where(r => !alive.Contains(r.Key)).ToList())
        {
            _rows.Remove(key);
            Processes.Remove(row);
        }

        var flagged = Processes.Count(r => r.IsFlagged);
        AlertCount = Processes.Count(r => r.Severity >= FindingSeverity.Medium);
        var hidden = Processes.Count(r => r.Path is null);
        StatusText = $"Updated {snapshot.Timestamp:T} · {Processes.Count} processes · {flagged} flagged"
            + (hidden > 0 ? $" · {hidden} hidden by Windows" : "");
    }
}
