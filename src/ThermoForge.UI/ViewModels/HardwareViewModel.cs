using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using ThermoForge.Core.Models;
using ThermoForge.Core.Providers;
using ThermoForge.Core.Services;

namespace ThermoForge.UI.ViewModels;

public sealed partial class HardwareViewModel : ObservableObject, IAsyncDisposable
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(1);

    /// <summary>10 minutes of history at the 1 s poll interval.</summary>
    private const int HistoryCapacity = 600;

    private readonly TemperatureThresholds _thresholds = TemperatureThresholds.Default;
    private readonly Dictionary<string, SensorRowViewModel> _rowsById = new();
    private SynchronizationContext? _uiContext;
    private SensorService? _service;
    private string? _startupError;

    public ObservableCollection<SensorRowViewModel> Sensors { get; } = new();
    public SensorHistory History { get; } = new(HistoryCapacity);

    public SummaryCardViewModel CpuTemperature { get; } = new("CPU temperature");
    public SummaryCardViewModel CpuLoad { get; } = new("CPU load");
    public SummaryCardViewModel GpuTemperature { get; } = new("GPU temperature");
    public SummaryCardViewModel GpuLoad { get; } = new("GPU load");
    public SummaryCardViewModel StorageTemperature { get; } = new("Hottest drive");
    public SummaryCardViewModel Fan { get; } = new("Fan");

    [ObservableProperty]
    private string _statusText = "Starting sensors…";

    /// <summary>Raised on the UI thread after a snapshot has been applied, so the view can redraw the chart.</summary>
    public event EventHandler? SnapshotApplied;

    public async Task StartAsync()
    {
        _uiContext = SynchronizationContext.Current
            ?? throw new InvalidOperationException("StartAsync must be called from the UI thread.");

        // Opening LibreHardwareMonitor probes every device and can take a few seconds.
        var (providers, startupError) = await Task.Run(CreateProviders);
        _startupError = startupError;

        _service = new SensorService(providers, PollInterval);
        _service.SnapshotAvailable += (_, snapshot) => _uiContext.Post(_ => Apply(snapshot), null);
        _service.Start();
    }

    public async ValueTask DisposeAsync()
    {
        if (_service is not null)
            await _service.DisposeAsync();
    }

    private static (IReadOnlyList<ISensorProvider> Providers, string? Error) CreateProviders()
    {
        var providers = new List<ISensorProvider> { new ThermalZoneSensorProvider() };
        try
        {
            providers.Insert(0, new LibreHardwareSensorProvider());
            return (providers, null);
        }
        catch (Exception ex)
        {
            // Keep the dashboard alive on ACPI zones alone.
            return (providers, $"LibreHardwareMonitor failed to start: {ex.Message}");
        }
    }

    private void Apply(SensorSnapshot snapshot)
    {
        History.Add(snapshot);
        var headlines = SensorSummary.HeadlineTemperatureIds(snapshot.Readings);

        foreach (var reading in snapshot.Readings)
        {
            if (!_rowsById.TryGetValue(reading.Id, out var row))
            {
                row = new SensorRowViewModel(reading, Sensors.Count, chartByDefault: headlines.Contains(reading.Id));
                _rowsById.Add(reading.Id, row);
                Sensors.Add(row);
            }
            row.Update(reading, History.GetStats(reading.Id), _thresholds.Evaluate(reading));
        }

        var summary = SensorSummary.From(snapshot.Readings);
        CpuTemperature.Update(summary.CpuTemperature, _thresholds);
        CpuLoad.Update(summary.CpuLoad, _thresholds);
        GpuTemperature.Update(summary.GpuTemperature, _thresholds);
        GpuLoad.Update(summary.GpuLoad, _thresholds);
        StorageTemperature.Update(summary.StorageTemperature, _thresholds);
        Fan.Update(summary.Fan, _thresholds);

        var errors = _startupError is null ? snapshot.Errors : [_startupError, .. snapshot.Errors];
        StatusText = errors.Count == 0
            ? $"Updated {snapshot.Timestamp:T} · {snapshot.Readings.Count} sensors"
            : $"Updated {snapshot.Timestamp:T} · {snapshot.Readings.Count} sensors · {string.Join("; ", errors)}";

        SnapshotApplied?.Invoke(this, EventArgs.Empty);
    }
}
