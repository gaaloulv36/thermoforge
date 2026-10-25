using System.Windows;
using System.Windows.Controls;
using ScottPlot;
using ThermoForge.Core.Models;
using ThermoForge.UI.ViewModels;

namespace ThermoForge.UI.Views;

public partial class HardwareView : UserControl
{
    private HardwareViewModel? _viewModel;

    public HardwareView()
    {
        InitializeComponent();
        StyleChart();
        DataContextChanged += OnDataContextChanged;
    }

    private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (_viewModel is not null)
            _viewModel.SnapshotApplied -= OnSnapshotApplied;

        _viewModel = e.NewValue as HardwareViewModel;
        if (_viewModel is not null)
            _viewModel.SnapshotApplied += OnSnapshotApplied;
    }

    private void OnSnapshotApplied(object? sender, SensorSnapshot e) => RenderChart();

    private void StyleChart()
    {
        var plot = TemperatureChart.Plot;
        plot.FigureBackground.Color = Color.FromHex("#1A1E24");
        plot.DataBackground.Color = Color.FromHex("#1A1E24");
        plot.Axes.Color(Color.FromHex("#8B95A3"));
        plot.Grid.MajorLineColor = Color.FromHex("#2B313A");
        plot.Legend.BackgroundColor = Color.FromHex("#20252C");
        plot.Legend.FontColor = Color.FromHex("#E6EAF0");
        plot.Legend.OutlineColor = Color.FromHex("#2B313A");
        plot.Axes.DateTimeTicksBottom();
        plot.YLabel("°C");
        plot.ShowLegend(Alignment.UpperLeft);
    }

    private void RenderChart()
    {
        // Skip the work while the Processes tab is showing.
        if (_viewModel is null || !IsVisible)
            return;

        var plot = TemperatureChart.Plot;
        plot.Clear();

        foreach (var row in _viewModel.Sensors.Where(r => r.IsCharted))
        {
            var (times, values) = _viewModel.History.GetSeries(row.Id);
            if (values.Length < 2)
                continue;

            var xs = times.Select(t => t.ToOADate()).ToArray();
            var line = plot.Add.Scatter(xs, values);
            line.LegendText = $"{row.Hardware} · {row.Name}";
            line.MarkerSize = 0;
            line.LineWidth = 2;
        }

        plot.Axes.AutoScale();
        TemperatureChart.Refresh();
    }
}
