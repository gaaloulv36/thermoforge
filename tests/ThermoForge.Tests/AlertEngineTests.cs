using ThermoForge.Core.Alerts;
using ThermoForge.Core.Models;
using ThermoForge.Core.Processes;
using ThermoForge.Core.Services;

namespace ThermoForge.Tests;

public class AlertEngineTests
{
    private static readonly DateTime T0 = new(2026, 1, 1, 12, 0, 0);
    private static readonly DateTime Started = new(2026, 1, 1, 11, 0, 0);

    private static ProcessInfo Proc(int pid, params FindingSeverity[] findings) => new(
        new RawProcess(pid, 0, $"app{pid}.exe", $@"C:\app{pid}.exe", null, Started),
        null, 0, 0, 0, null,
        findings.Select(s => new ProcessFinding(s, $"{s} thing", "detail")).ToList());

    private static ProcessSnapshot Snap(DateTime time, params ProcessInfo[] processes) => new(time, processes);

    private static SensorSnapshot Cpu(DateTime time, double celsius) => new(time,
        [new SensorReading("/cpu/0/temperature/0", "Intel Core i7", HardwareCategory.Cpu, "CPU Package", SensorKind.Temperature, celsius)],
        []);

    [Fact]
    public void ProcessesRiskyAtStartup_DoNotAlertIndividually()
    {
        var engine = new AlertEngine(TemperatureThresholds.Default);

        Assert.Empty(engine.Evaluate(Snap(T0, Proc(1, FindingSeverity.High))));
        Assert.Empty(engine.Evaluate(Snap(T0.AddSeconds(3), Proc(1, FindingSeverity.High))));
    }

    [Fact]
    public void NewRiskyProcess_AlertsOnce()
    {
        var engine = new AlertEngine(TemperatureThresholds.Default);
        engine.Evaluate(Snap(T0));

        var first = engine.Evaluate(Snap(T0.AddSeconds(3), Proc(5, FindingSeverity.Medium)));
        var again = engine.Evaluate(Snap(T0.AddSeconds(6), Proc(5, FindingSeverity.Medium)));

        var alert = Assert.Single(first);
        Assert.Equal(FindingSeverity.Medium, alert.Severity);
        Assert.Equal(5, alert.Pid);
        Assert.Contains("app5.exe", alert.Title);
        Assert.Empty(again);
    }

    [Fact]
    public void ProcessGettingWorse_AlertsAgain()
    {
        var engine = new AlertEngine(TemperatureThresholds.Default);
        engine.Evaluate(Snap(T0, Proc(5, FindingSeverity.Low)));

        var worse = engine.Evaluate(Snap(T0.AddSeconds(3), Proc(5, FindingSeverity.Low, FindingSeverity.High)));

        Assert.Equal(FindingSeverity.High, Assert.Single(worse).Severity);
    }

    [Fact]
    public void LowRisk_DoesNotAlertByDefault()
    {
        var engine = new AlertEngine(TemperatureThresholds.Default);
        engine.Evaluate(Snap(T0));

        Assert.Empty(engine.Evaluate(Snap(T0.AddSeconds(3), Proc(5, FindingSeverity.Low))));
    }

    [Fact]
    public void StartupSummary_GroupsSeveralRiskyProcesses()
    {
        var snapshot = Snap(T0, Proc(1, FindingSeverity.High), Proc(2, FindingSeverity.Medium), Proc(3, FindingSeverity.Low));

        var alert = Assert.Single(AlertEngine.StartupSummary(snapshot, FindingSeverity.Medium));

        Assert.Equal(FindingSeverity.High, alert.Severity);
        Assert.StartsWith("2 risky", alert.Title);
    }

    [Fact]
    public void BriefTemperatureSpike_DoesNotAlert()
    {
        var engine = new AlertEngine(TemperatureThresholds.Default);

        Assert.Empty(engine.Evaluate(Cpu(T0, 95)));
        Assert.Empty(engine.Evaluate(Cpu(T0.AddSeconds(5), 95)));
        Assert.Empty(engine.Evaluate(Cpu(T0.AddSeconds(6), 70)));
        Assert.Empty(engine.Evaluate(Cpu(T0.AddSeconds(20), 95)));
    }

    [Fact]
    public void SustainedHeat_AlertsThenCoolsDown()
    {
        var engine = new AlertEngine(TemperatureThresholds.Default);
        var alerts = new List<Alert>();
        for (var s = 0; s <= 120; s++)
            alerts.AddRange(engine.Evaluate(Cpu(T0.AddSeconds(s), 95)));

        var alert = Assert.Single(alerts);
        Assert.Equal(AlertKind.Temperature, alert.Kind);
        Assert.Contains("95 °C", alert.Message);

        // After the cooldown it may alert again.
        Assert.Single(engine.Evaluate(Cpu(T0 + AlertEngine.TemperatureCooldown + TimeSpan.FromSeconds(30), 95)));
    }
}
