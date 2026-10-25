using System.Globalization;
using LibreHardwareMonitor.Hardware;
using ThermoForge.Core.Models;

namespace ThermoForge.Core.Providers;

/// <summary>
/// Reads CPU, GPU, storage, motherboard and fan sensors through LibreHardwareMonitor.
/// Most CPU/motherboard sensors need admin rights and the PawnIO driver; without them
/// this provider still returns what it can (GPU, storage, load).
/// </summary>
public sealed class LibreHardwareSensorProvider : ISensorProvider
{
    private readonly Computer _computer;
    private readonly UpdateVisitor _visitor = new();

    public LibreHardwareSensorProvider()
    {
        _computer = new Computer
        {
            IsCpuEnabled = true,
            IsGpuEnabled = true,
            IsMemoryEnabled = true,
            IsMotherboardEnabled = true,
            IsControllerEnabled = true,
            IsStorageEnabled = true,
            IsBatteryEnabled = true,
        };
        _computer.Open();
    }

    public string Name => "LibreHardwareMonitor";

    public IReadOnlyList<SensorReading> Read()
    {
        _computer.Accept(_visitor);

        var readings = new List<SensorReading>();
        foreach (var hardware in _computer.Hardware)
            Collect(hardware, MapCategory(hardware.HardwareType), readings);
        return readings;
    }

    public void Dispose() => _computer.Close();

    private static void Collect(IHardware hardware, HardwareCategory category, List<SensorReading> readings)
    {
        foreach (var sensor in hardware.Sensors)
        {
            if (sensor.Value is not float value || float.IsNaN(value))
                continue;

            readings.Add(new SensorReading(
                sensor.Identifier.ToString(),
                CleanName(hardware.Name),
                category,
                sensor.Name,
                MapKind(sensor.SensorType),
                value));
        }

        // Sub-hardware (e.g. Super I/O chips on a motherboard) inherits the parent's category.
        foreach (var sub in hardware.SubHardware)
            Collect(sub, category, readings);
    }

    /// <summary>
    /// Some memory modules report SPD part numbers containing raw non-printable bytes,
    /// which render as boxes. Drop those so device names stay readable.
    /// </summary>
    internal static string CleanName(string name)
    {
        var printable = name.Select(c => char.IsWhiteSpace(c) ? ' ' : c).Where(c => c != '�' && char.GetUnicodeCategory(c) is not (
            UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.PrivateUse
            or UnicodeCategory.Surrogate or UnicodeCategory.OtherNotAssigned));
        return string.Join(' ', new string(printable.ToArray()).Split(' ', StringSplitOptions.RemoveEmptyEntries));
    }

    private static HardwareCategory MapCategory(HardwareType type) => type switch
    {
        HardwareType.Cpu => HardwareCategory.Cpu,
        HardwareType.GpuNvidia or HardwareType.GpuAmd or HardwareType.GpuIntel => HardwareCategory.Gpu,
        HardwareType.Memory => HardwareCategory.Memory,
        HardwareType.Storage => HardwareCategory.Storage,
        HardwareType.Motherboard or HardwareType.SuperIO or HardwareType.EmbeddedController => HardwareCategory.Motherboard,
        HardwareType.Cooler or HardwareType.Psu => HardwareCategory.Controller,
        HardwareType.Battery => HardwareCategory.Battery,
        _ => HardwareCategory.Other,
    };

    private static SensorKind MapKind(SensorType type) => type switch
    {
        SensorType.Temperature => SensorKind.Temperature,
        SensorType.Load => SensorKind.Load,
        SensorType.Clock => SensorKind.Clock,
        SensorType.Fan => SensorKind.Fan,
        SensorType.Power => SensorKind.Power,
        SensorType.Voltage => SensorKind.Voltage,
        SensorType.Level or SensorType.Control => SensorKind.Level,
        SensorType.Data => SensorKind.Data,
        SensorType.SmallData => SensorKind.SmallData,
        SensorType.Throughput => SensorKind.Throughput,
        _ => SensorKind.Other,
    };

    private sealed class UpdateVisitor : IVisitor
    {
        public void VisitComputer(IComputer computer) => computer.Traverse(this);

        public void VisitHardware(IHardware hardware)
        {
            hardware.Update();
            foreach (var sub in hardware.SubHardware)
                sub.Accept(this);
        }

        public void VisitSensor(ISensor sensor) { }

        public void VisitParameter(IParameter parameter) { }
    }
}
