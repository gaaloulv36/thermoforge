namespace ThermoForge.Core.Models;

/// <summary>All readings from one poll, plus any providers that failed during it.</summary>
public sealed record SensorSnapshot(
    DateTime Timestamp,
    IReadOnlyList<SensorReading> Readings,
    IReadOnlyList<string> Errors);
