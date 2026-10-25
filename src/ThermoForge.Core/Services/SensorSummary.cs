using ThermoForge.Core.Models;

namespace ThermoForge.Core.Services;

/// <summary>Picks the headline sensor for each dashboard card from a raw snapshot.</summary>
public sealed record SensorSummary(
    SensorReading? CpuTemperature,
    SensorReading? CpuLoad,
    SensorReading? GpuTemperature,
    SensorReading? GpuLoad,
    SensorReading? StorageTemperature,
    SensorReading? Fan)
{
    public static SensorSummary From(IReadOnlyList<SensorReading> readings)
    {
        var cpuTemps = Temperatures(readings, HardwareCategory.Cpu);
        var cpuTemperature =
            Named(cpuTemps, "CPU Package")
            ?? Named(cpuTemps, "Core Max")
            ?? Hottest(cpuTemps)
            // No CPU sensors (no admin / PawnIO): ACPI zones are the best approximation.
            ?? Hottest(Temperatures(readings, HardwareCategory.ThermalZone));

        var cpuLoads = Of(readings, HardwareCategory.Cpu, SensorKind.Load);
        var gpuTemps = Temperatures(readings, HardwareCategory.Gpu);
        var gpuLoads = Of(readings, HardwareCategory.Gpu, SensorKind.Load);

        return new SensorSummary(
            cpuTemperature,
            Named(cpuLoads, "CPU Total") ?? Hottest(cpuLoads),
            Named(gpuTemps, "GPU Core") ?? Hottest(gpuTemps),
            Named(gpuLoads, "GPU Core") ?? Hottest(gpuLoads),
            Hottest(Temperatures(readings, HardwareCategory.Storage)),
            Hottest(readings.Where(r => r.Kind == SensorKind.Fan)));
    }

    /// <summary>Sensor names that best represent a device's temperature, in priority order.</summary>
    private static readonly string[] HeadlineNames = ["CPU Package", "GPU Core", "Composite Temperature", "Temperature"];

    /// <summary>
    /// One representative temperature per device (package, GPU core, drive composite, or the
    /// hottest otherwise). Used as the default chart selection so the chart stays readable.
    /// </summary>
    public static IReadOnlySet<string> HeadlineTemperatureIds(IEnumerable<SensorReading> readings) =>
        readings
            .Where(r => r.IsMeasuredTemperature)
            .GroupBy(r => r.Hardware)
            .Select(device =>
                HeadlineNames.Select(name => Named(device, name)).FirstOrDefault(r => r is not null)
                ?? Hottest(device)!)
            .Select(r => r.Id)
            .ToHashSet();

    private static IEnumerable<SensorReading> Temperatures(IEnumerable<SensorReading> readings, HardwareCategory category) =>
        readings.Where(r => r.Category == category && r.IsMeasuredTemperature);

    private static IEnumerable<SensorReading> Of(IEnumerable<SensorReading> readings, HardwareCategory category, SensorKind kind) =>
        readings.Where(r => r.Category == category && r.Kind == kind);

    private static SensorReading? Named(IEnumerable<SensorReading> readings, string name) =>
        readings.FirstOrDefault(r => r.Name.Equals(name, StringComparison.OrdinalIgnoreCase));

    private static SensorReading? Hottest(IEnumerable<SensorReading> readings) =>
        readings.MaxBy(r => r.Value);
}
