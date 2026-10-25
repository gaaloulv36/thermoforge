using CommunityToolkit.Mvvm.ComponentModel;
using ThermoForge.Core.Models;
using ThermoForge.Core.Services;

namespace ThermoForge.UI.ViewModels;

public sealed partial class SensorRowViewModel : ObservableObject
{
    public SensorRowViewModel(SensorReading reading, int order, bool chartByDefault)
    {
        Id = reading.Id;
        Order = order;
        Hardware = reading.Hardware;
        Name = reading.Name;
        Kind = reading.Kind;
        IsChartable = reading.IsMeasuredTemperature;
        _isCharted = IsChartable && chartByDefault;
    }

    public string Id { get; }

    /// <summary>Discovery order; keeps the provider's natural sensor order within a device when sorting.</summary>
    public int Order { get; }
    public string Hardware { get; }
    public string Name { get; }
    public SensorKind Kind { get; }
    public bool IsChartable { get; }

    [ObservableProperty]
    private bool _isCharted;

    [ObservableProperty]
    private string _value = SensorFormatter.Missing;

    [ObservableProperty]
    private string _min = SensorFormatter.Missing;

    [ObservableProperty]
    private string _max = SensorFormatter.Missing;

    [ObservableProperty]
    private TemperatureStatus _status;

    public void Update(SensorReading reading, SensorStats? stats, TemperatureStatus status)
    {
        Value = SensorFormatter.Format(Kind, reading.Value);
        Min = SensorFormatter.Format(Kind, stats?.Min);
        Max = SensorFormatter.Format(Kind, stats?.Max);
        Status = status;
    }
}
