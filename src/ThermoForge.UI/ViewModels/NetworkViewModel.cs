using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ThermoForge.Core.Network;
using ThermoForge.Core.Processes;

namespace ThermoForge.UI.ViewModels;

/// <summary>
/// The Network tab: every connection and listening port, with the program behind it. Fed by the
/// process snapshots, so it updates with the Processes tab and shows the same PIDs.
/// </summary>
public sealed partial class NetworkViewModel : ObservableObject
{
    private readonly Dictionary<(NetProtocol, IPEndPoint, IPEndPoint?, int), ConnectionRowViewModel> _rows = new();

    public NetworkViewModel()
    {
        ConnectionsView = new ListCollectionView(Connections)
        {
            Filter = Matches,
            IsLiveSorting = true,
            IsLiveFiltering = true,
        };
        ConnectionsView.SortDescriptions.Add(new SortDescription(nameof(ConnectionRowViewModel.Risk), ListSortDirection.Descending));
        ConnectionsView.SortDescriptions.Add(new SortDescription(nameof(ConnectionRowViewModel.ProcessName), ListSortDirection.Ascending));
        ConnectionsView.SortDescriptions.Add(new SortDescription(nameof(ConnectionRowViewModel.IsListening), ListSortDirection.Ascending));
        ConnectionsView.LiveFilteringProperties.Add(nameof(ConnectionRowViewModel.Severity));
    }

    public ObservableCollection<ConnectionRowViewModel> Connections { get; } = new();
    public ListCollectionView ConnectionsView { get; }

    /// <summary>The user wants to see the selected connection's process on the Processes tab.</summary>
    public event EventHandler<int>? ProcessRequested;

    [ObservableProperty]
    private string _searchText = "";

    [ObservableProperty]
    private bool _showFlaggedOnly;

    [ObservableProperty]
    private bool _hideThisPc = true;

    [ObservableProperty]
    private bool _showListening = true;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ShowProcessCommand), nameof(CopyAddressCommand), nameof(CheckAddressOnlineCommand))]
    private ConnectionRowViewModel? _selectedConnection;

    [ObservableProperty]
    private string _statusText = "Reading connections…";

    /// <summary>Programs with a Medium or High network finding; shown as a badge on the tab.</summary>
    [ObservableProperty]
    private int _alertCount;

    partial void OnSearchTextChanged(string value) => ConnectionsView.Refresh();

    partial void OnShowFlaggedOnlyChanged(bool value) => ConnectionsView.Refresh();

    partial void OnHideThisPcChanged(bool value) => ConnectionsView.Refresh();

    partial void OnShowListeningChanged(bool value) => ConnectionsView.Refresh();

    [RelayCommand(CanExecute = nameof(HasSelection))]
    private void ShowProcess() => ProcessRequested?.Invoke(this, SelectedConnection!.Pid);

    [RelayCommand(CanExecute = nameof(HasSelection))]
    private void CopyAddress()
    {
        try
        {
            Clipboard.SetText(SelectedConnection!.Address);
        }
        catch (COMException)
        {
            // Another app is holding the clipboard.
        }
    }

    private bool HasSelection() => SelectedConnection is not null;

    /// <summary>Opens the address's abuse reports in the browser; nothing is sent until the user clicks.</summary>
    [RelayCommand(CanExecute = nameof(CanLookUp))]
    private void CheckAddressOnline() =>
        Process.Start(new ProcessStartInfo($"https://www.abuseipdb.com/check/{Uri.EscapeDataString(SelectedConnection!.Address)}")
            { UseShellExecute = true });

    private bool CanLookUp() => SelectedConnection is { CanLookUp: true };

    private bool Matches(object item)
    {
        var row = (ConnectionRowViewModel)item;
        if (ShowFlaggedOnly && !row.IsFlagged)
            return false;
        if (HideThisPc && row.IsThisPc)
            return false;
        if (!ShowListening && row.IsListening)
            return false;
        if (string.IsNullOrWhiteSpace(SearchText))
            return true;

        var term = SearchText.Trim();
        return row.ProcessName.Contains(term, StringComparison.OrdinalIgnoreCase)
            || row.Pid.ToString().Equals(term, StringComparison.Ordinal)
            || row.RemoteText.Contains(term, StringComparison.OrdinalIgnoreCase)
            || row.LocalText.Contains(term, StringComparison.OrdinalIgnoreCase)
            || row.HostText.Contains(term, StringComparison.OrdinalIgnoreCase)
            || row.Publisher.Contains(term, StringComparison.OrdinalIgnoreCase);
    }

    public void Apply(ProcessSnapshot snapshot)
    {
        var processes = snapshot.Processes.ToDictionary(p => p.Process.Pid);
        var alive = new HashSet<(NetProtocol, IPEndPoint, IPEndPoint?, int)>();
        foreach (var connection in snapshot.Connections)
        {
            var raw = connection.Raw;
            var key = (raw.Protocol, raw.Local, raw.Remote, raw.Pid);
            if (!alive.Add(key))
                continue;

            var process = processes.GetValueOrDefault(raw.Pid);
            if (_rows.TryGetValue(key, out var row))
            {
                row.Update(connection, process);
            }
            else
            {
                row = new ConnectionRowViewModel(connection, process);
                _rows.Add(key, row);
                Connections.Add(row);
            }
        }

        foreach (var (key, row) in _rows.Where(r => !alive.Contains(r.Key)).ToList())
        {
            _rows.Remove(key);
            Connections.Remove(row);
        }

        AlertCount = Connections.Where(r => r.Severity >= FindingSeverity.Medium).Select(r => r.Pid).Distinct().Count();
        var internet = Connections.Count(r => r.Scope == RemoteScope.Internet);
        var listening = Connections.Count(r => r.IsListening);
        var programs = Connections.Select(r => r.Pid).Distinct().Count();
        StatusText = snapshot.NetworkError is { } error
            ? $"Could not read connections: {error}"
            : $"Updated {snapshot.Timestamp:T} · {internet} to the internet · {listening} listening · {programs} programs"
              + $" · {Connections.Count(r => r.IsFlagged)} flagged";
    }
}
