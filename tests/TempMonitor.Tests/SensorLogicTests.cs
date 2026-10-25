using System.Globalization;
using TempMonitor.Core.Models;
using TempMonitor.Core.Services;

namespace TempMonitor.Tests;

public class TemperatureThresholdsTests
{
    private static SensorReading Temp(HardwareCategory category, double value, string name = "Temp") =>
        new("id", "hw", category, name, SensorKind.Temperature, value);

    [Theory]
    [InlineData(65, TemperatureStatus.Normal)]
    [InlineData(80, TemperatureStatus.Warm)]
    [InlineData(90, TemperatureStatus.Hot)]
    public void Cpu_UsesCpuThresholds(double value, TemperatureStatus expected) =>
        Assert.Equal(expected, TemperatureThresholds.Default.Evaluate(Temp(HardwareCategory.Cpu, value)));

    [Fact]
    public void Storage_IsHotAtLowerTemperatureThanCpu() =>
        Assert.Equal(TemperatureStatus.Hot, TemperatureThresholds.Default.Evaluate(Temp(HardwareCategory.Storage, 72)));

    [Fact]
    public void DistanceToTjMax_IsNotEvaluated() =>
        Assert.Equal(TemperatureStatus.Unknown,
            TemperatureThresholds.Default.Evaluate(Temp(HardwareCategory.Cpu, 10, "CPU Core #1 Distance to TjMax")));

    [Fact]
    public void NonTemperature_IsNotEvaluated() =>
        Assert.Equal(TemperatureStatus.Unknown, TemperatureThresholds.Default.Evaluate(
            new SensorReading("id", "hw", HardwareCategory.Cpu, "CPU Total", SensorKind.Load, 99)));
}

public class SensorSummaryTests
{
    private static SensorReading R(HardwareCategory category, string name, SensorKind kind, double value) =>
        new($"{category}/{name}", category.ToString(), category, name, kind, value);

    [Fact]
    public void PrefersCpuPackageOverHotterCore()
    {
        var summary = SensorSummary.From([
            R(HardwareCategory.Cpu, "CPU Core #1", SensorKind.Temperature, 88),
            R(HardwareCategory.Cpu, "CPU Package", SensorKind.Temperature, 80),
        ]);

        Assert.Equal("CPU Package", summary.CpuTemperature?.Name);
    }

    [Fact]
    public void IgnoresDistanceToTjMaxWhenPickingHottest()
    {
        var summary = SensorSummary.From([
            R(HardwareCategory.Cpu, "CPU Core #1", SensorKind.Temperature, 60),
            R(HardwareCategory.Cpu, "CPU Core #1 Distance to TjMax", SensorKind.Temperature, 40),
        ]);

        Assert.Equal(60, summary.CpuTemperature?.Value);
    }

    [Fact]
    public void FallsBackToThermalZoneWhenNoCpuTemperature()
    {
        var summary = SensorSummary.From([
            R(HardwareCategory.Cpu, "CPU Total", SensorKind.Load, 12),
            R(HardwareCategory.ThermalZone, "TZ00", SensorKind.Temperature, 45),
            R(HardwareCategory.ThermalZone, "TZ01", SensorKind.Temperature, 52),
        ]);

        Assert.Equal("TZ01", summary.CpuTemperature?.Name);
        Assert.Equal("CPU Total", summary.CpuLoad?.Name);
    }

    [Fact]
    public void IgnoresNvmeThresholdSensorsWhenPickingHottestDrive()
    {
        var summary = SensorSummary.From([
            R(HardwareCategory.Storage, "Composite Temperature", SensorKind.Temperature, 42),
            R(HardwareCategory.Storage, "Warning Temperature", SensorKind.Temperature, 90),
            R(HardwareCategory.Storage, "Critical Temperature", SensorKind.Temperature, 109),
            R(HardwareCategory.Storage, "Thermal Sensor High Limit", SensorKind.Temperature, 100),
        ]);

        Assert.Equal(42, summary.StorageTemperature?.Value);
    }

    [Fact]
    public void HeadlineTemperatures_PicksOnePerDevice()
    {
        SensorReading On(string hardware, string name, double value) =>
            new($"{hardware}/{name}", hardware, HardwareCategory.Other, name, SensorKind.Temperature, value);

        var ids = SensorSummary.HeadlineTemperatureIds([
            On("CPU", "CPU Core #1", 70),
            On("CPU", "CPU Package", 65),
            On("SSD", "Critical Temperature", 109),
            On("SSD", "Composite Temperature", 40),
            On("ACPI", "TZ00", 45),
            On("ACPI", "TZ01", 58),
        ]);

        Assert.Equal(["ACPI/TZ01", "CPU/CPU Package", "SSD/Composite Temperature"], ids.Order());
    }

    [Fact]
    public void PicksHottestDriveAndFastestFan()
    {
        var summary = SensorSummary.From([
            R(HardwareCategory.Storage, "Temperature", SensorKind.Temperature, 41),
            R(HardwareCategory.Storage, "Temperature 2", SensorKind.Temperature, 55),
            R(HardwareCategory.Motherboard, "Fan #1", SensorKind.Fan, 1200),
            R(HardwareCategory.Motherboard, "Fan #2", SensorKind.Fan, 2400),
        ]);

        Assert.Equal(55, summary.StorageTemperature?.Value);
        Assert.Equal(2400, summary.Fan?.Value);
        Assert.Null(summary.GpuTemperature);
    }
}

public class SensorFormatterTests
{
    public SensorFormatterTests() => CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;

    [Theory]
    [InlineData(SensorKind.Temperature, 45.26, "45.3 °C")]
    [InlineData(SensorKind.Load, 12.6, "13 %")]
    [InlineData(SensorKind.Fan, 2400, "2400 RPM")]
    [InlineData(SensorKind.Throughput, 1536, "1.5 KB/s")]
    [InlineData(SensorKind.Throughput, 3 * 1024 * 1024, "3.0 MB/s")]
    public void FormatsWithUnit(SensorKind kind, double value, string expected) =>
        Assert.Equal(expected, SensorFormatter.Format(kind, value));

    [Fact]
    public void MissingValue_ShowsDash() =>
        Assert.Equal(SensorFormatter.Missing, SensorFormatter.Format(SensorKind.Temperature, null));
}
