using ThermoForge.Core.Models;

namespace ThermoForge.Core.Providers;

public interface ISensorProvider : IDisposable
{
    string Name { get; }

    /// <summary>Refreshes the underlying hardware and returns current values. Called from a single polling thread.</summary>
    IReadOnlyList<SensorReading> Read();
}
