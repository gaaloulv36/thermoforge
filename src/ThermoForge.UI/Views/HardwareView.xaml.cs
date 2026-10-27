using System.Windows;
using System.Windows.Controls;
using ScottPlot;
using ThermoForge.Core.Models;
using ThermoForge.UI.ViewModels;

namespace ThermoForge.UI.Views;

public partial class HardwareView : UserControl
{
    /// <summary>Open Forge Studio's product tones, so the chart matches the rest of the brand.</summary>
    private static readonly string[] SeriesColors =
        ["#22D3EE", "#F97316", "#34D399", "#A78BFA", "#FBBF24", "#FB7185", "#7DD3FC", "#F472B6"];

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
        plot.FigureBackground.Color = Color.FromHex("#121A2B");
        plot.DataBackground.Color = Color.FromHex("#121A2B");
        plot.Axes.Color(Color.FromHex("#94A3B8"));
        plot.Grid.MajorLineColor = Color.FromHex("#1E293B");
        plot.Legend.BackgroundColor = Color.FromHex("#0F1626");
        plot.Legend.FontColor = Color.FromHex("#F8FAFC");
        plot.Legend.OutlineColor = Color.FromHex("#1E293B");
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

        var index = 0;
        foreach (var row in _viewModel.Sensors.Where(r => r.IsCharted))
        {
            var (times, values) = _viewModel.History.GetSeries(row.Id);
            if (values.Length < 2)
                continue;

            var xs = times.Select(t => t.ToOADate()).ToArray();
            var line = plot.Add.Scatter(xs, values);
            line.LegendText = $"{row.Hardware} · {row.Name}";
            line.Color = Color.FromHex(SeriesColors[index++ % SeriesColors.Length]);
            line.MarkerSize = 0;
            line.LineWidth = 2;
        }

        plot.Axes.AutoScale();
        TemperatureChart.Refresh();
    }
}
