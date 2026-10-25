using ThermoForge.Core.Models;
using ThermoForge.Core.Providers;

namespace ThermoForge.Core.Services;

/// <summary>
/// Polls every sensor provider on one background loop and raises <see cref="SnapshotAvailable"/>
/// after each poll. The event fires on the polling thread; subscribers marshal to the UI.
/// </summary>
public sealed class SensorService : IAsyncDisposable
{
    private readonly IReadOnlyList<ISensorProvider> _providers;
    private readonly PollingLoop<SensorSnapshot> _loop;

    public SensorService(IReadOnlyList<ISensorProvider> providers, TimeSpan interval)
    {
        _providers = providers;
        _loop = new PollingLoop<SensorSnapshot>(Poll, interval);
    }

    public event EventHandler<SensorSnapshot>? SnapshotAvailable
    {
        add => _loop.Polled += value;
        remove => _loop.Polled -= value;
    }

    public void Start() => _loop.Start();

    public SensorSnapshot Poll()
    {
        var readings = new List<SensorReading>();
        var errors = new List<string>();

        foreach (var provider in _providers)
        {
            try
            {
                readings.AddRange(provider.Read());
            }
            catch (Exception ex)
            {
                // One broken provider must not stop the others.
                errors.Add($"{provider.Name}: {ex.Message}");
            }
        }

        return new SensorSnapshot(DateTime.Now, readings, errors);
    }

    public async ValueTask DisposeAsync()
    {
        await _loop.DisposeAsync();
        foreach (var provider in _providers)
            provider.Dispose();
    }
}
