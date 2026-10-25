using TempMonitor.Core.Models;
using TempMonitor.Core.Services;

namespace TempMonitor.Tests;

public class SensorHistoryTests
{
    private static SensorSnapshot Snapshot(int second, double value) => new(
        new DateTime(2026, 1, 1, 12, 0, second),
        [new SensorReading("cpu", "CPU", HardwareCategory.Cpu, "CPU Package", SensorKind.Temperature, value)],
        []);

    [Fact]
    public void GetSeries_ReturnsPointsInOrder()
    {
        var history = new SensorHistory(capacity: 5);
        history.Add(Snapshot(0, 40));
        history.Add(Snapshot(1, 41));
        history.Add(Snapshot(2, 42));

        var (times, values) = history.GetSeries("cpu");

        Assert.Equal([40, 41, 42], values);
        Assert.Equal(2, times[^1].Second);
    }

    [Fact]
    public void GetSeries_DropsOldestWhenFull()
    {
        var history = new SensorHistory(capacity: 3);
        for (var i = 0; i < 5; i++)
            history.Add(Snapshot(i, 50 + i));

        var (times, values) = history.GetSeries("cpu");

        Assert.Equal([52, 53, 54], values);
        Assert.Equal([2, 3, 4], times.Select(t => t.Second));
    }

    [Fact]
    public void GetStats_TracksSessionMinMaxBeyondBufferWindow()
    {
        var history = new SensorHistory(capacity: 2);
        history.Add(Snapshot(0, 95));
        history.Add(Snapshot(1, 60));
        history.Add(Snapshot(2, 30));

        Assert.Equal(new SensorStats(30, 95), history.GetStats("cpu"));
    }

    [Fact]
    public void UnknownSensor_ReturnsEmpty()
    {
        var history = new SensorHistory(capacity: 2);

        Assert.Null(history.GetStats("missing"));
        Assert.Empty(history.GetSeries("missing").Values);
    }
}
