using System.Management;
using TempMonitor.Core.Models;

namespace TempMonitor.Core.Providers;

/// <summary>
/// Reads ACPI thermal zones through Windows performance counters. Works without admin
/// rights or a kernel driver, so it is the fallback when LibreHardwareMonitor cannot
/// reach the CPU sensors. Zones are firmware-defined and usually sit near the CPU/chassis.
/// </summary>
public sealed class ThermalZoneSensorProvider : ISensorProvider
{
    private const string Query =
        "SELECT Name, HighPrecisionTemperature FROM Win32_PerfFormattedData_Counters_ThermalZoneInformation";

    private readonly ManagementObjectSearcher _searcher = new("root\\CIMV2", Query);

    public string Name => "ACPI thermal zones";

    public IReadOnlyList<SensorReading> Read()
    {
        var readings = new List<SensorReading>();
        using var results = _searcher.Get();
        foreach (var obj in results)
        {
            using (obj)
            {
                // Reported in tenths of a Kelvin. Unused zones report ~273.2 K (0 °C); skip them.
                var celsius = Math.Round(Convert.ToDouble(obj["HighPrecisionTemperature"]) / 10.0 - 273.15, 1);
                if (celsius < 1)
                    continue;

                var zone = ((obj["Name"] as string) ?? "Zone").Replace(@"\_TZ.", "");
                readings.Add(new SensorReading(
                    $"/acpi/thermalzone/{zone}",
                    "ACPI Thermal Zones",
                    HardwareCategory.ThermalZone,
                    zone,
                    SensorKind.Temperature,
                    celsius));
            }
        }
        return readings;
    }

    public void Dispose() => _searcher.Dispose();
}
