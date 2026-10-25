using CommunityToolkit.Mvvm.ComponentModel;
using ThermoForge.Core.Models;
using ThermoForge.Core.Services;

namespace ThermoForge.UI.ViewModels;

public sealed partial class SummaryCardViewModel(string title) : ObservableObject
{
    public string Title { get; } = title;

    [ObservableProperty]
    private string _value = SensorFormatter.Missing;

    [ObservableProperty]
    private string _source = "No sensor";

    [ObservableProperty]
    private TemperatureStatus _status = TemperatureStatus.Unknown;

    public void Update(SensorReading? reading, TemperatureThresholds thresholds)
    {
        if (reading is null)
        {
            Value = SensorFormatter.Missing;
            Source = "No sensor";
            Status = TemperatureStatus.Unknown;
            return;
        }

        Value = SensorFormatter.Format(reading.Kind, reading.Value);
        Source = $"{reading.Hardware} · {reading.Name}";
        Status = thresholds.Evaluate(reading);
    }
}
