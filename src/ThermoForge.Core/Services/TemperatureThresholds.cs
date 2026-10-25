using ThermoForge.Core.Models;

namespace ThermoForge.Core.Services;

public enum TemperatureStatus
{
    Unknown,
    Normal,
    Warm,
    Hot,
}

public sealed record ThresholdPair(double Warm, double Hot);

public sealed class TemperatureThresholds
{
    private readonly IReadOnlyDictionary<HardwareCategory, ThresholdPair> _byCategory;
    private readonly ThresholdPair _fallback;

    public TemperatureThresholds(IReadOnlyDictionary<HardwareCategory, ThresholdPair> byCategory, ThresholdPair fallback)
    {
        _byCategory = byCategory;
        _fallback = fallback;
    }

    /// <summary>Conservative defaults for laptops/desktops, in °C.</summary>
    public static TemperatureThresholds Default { get; } = new(
        new Dictionary<HardwareCategory, ThresholdPair>
        {
            [HardwareCategory.Cpu] = new(80, 90),
            [HardwareCategory.Gpu] = new(75, 85),
            [HardwareCategory.Storage] = new(60, 70),
            [HardwareCategory.Battery] = new(45, 55),
        },
        fallback: new(70, 85));

    public ThresholdPair For(HardwareCategory category) =>
        _byCategory.TryGetValue(category, out var pair) ? pair : _fallback;

    public TemperatureStatus Evaluate(SensorReading reading)
    {
        if (!reading.IsMeasuredTemperature)
            return TemperatureStatus.Unknown;

        var pair = For(reading.Category);
        if (reading.Value >= pair.Hot)
            return TemperatureStatus.Hot;
        return reading.Value >= pair.Warm ? TemperatureStatus.Warm : TemperatureStatus.Normal;
    }
}
