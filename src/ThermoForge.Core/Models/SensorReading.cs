namespace ThermoForge.Core.Models;

public enum HardwareCategory
{
    Cpu,
    Gpu,
    Memory,
    Storage,
    Motherboard,
    Controller,
    Battery,
    ThermalZone,
    Other,
}

public enum SensorKind
{
    Temperature,
    Load,
    Clock,
    Fan,
    Power,
    Voltage,
    Level,
    Data,
    SmallData,
    Throughput,
    Other,
}

/// <summary>A single sensor value captured at poll time.</summary>
/// <param name="Id">Stable identifier, unique across providers (e.g. "/intelcpu/0/temperature/0").</param>
public sealed record SensorReading(
    string Id,
    string Hardware,
    HardwareCategory Category,
    string Name,
    SensorKind Kind,
    double Value)
{
    /// <summary>
    /// Sensors typed as temperatures that are not measurements: Intel's "Distance to TjMax"
    /// headroom delta, and the fixed thresholds NVMe drives report ("Critical Temperature",
    /// "Thermal Sensor High Limit", "Temperature Sensor Resolution", ...).
    /// </summary>
    private static readonly string[] NonMeasurementMarkers =
        ["Distance to TjMax", "Limit", "Resolution", "Warning Temperature", "Critical Temperature"];

    /// <summary>True for live temperature measurements (excludes deltas and fixed thresholds).</summary>
    public bool IsMeasuredTemperature =>
        Kind == SensorKind.Temperature
        && !NonMeasurementMarkers.Any(m => Name.Contains(m, StringComparison.OrdinalIgnoreCase));
}
