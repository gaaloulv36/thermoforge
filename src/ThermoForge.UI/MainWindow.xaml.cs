using System.ComponentModel;
using System.Windows;
using ThermoForge.UI.ViewModels;

namespace ThermoForge.UI;

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel = new();
    private bool _monitorsStopped;

    public MainWindow()
    {
        InitializeComponent();
        FitToWorkArea();
        DataContext = _viewModel;
        Loaded += async (_, _) => await _viewModel.StartAsync();
    }

    /// <summary>Laptops at 125–150 % scaling have less room than the default size; never open partly off-screen.</summary>
    private void FitToWorkArea()
    {
        var area = SystemParameters.WorkArea;
        Width = Math.Min(Width, area.Width - 40);
        Height = Math.Min(Height, area.Height - 40);
        MinWidth = Math.Min(MinWidth, Width);
        MinHeight = Math.Min(MinHeight, Height);
    }

    protected override async void OnClosing(CancelEventArgs e)
    {
        if (_monitorsStopped)
        {
            base.OnClosing(e);
            return;
        }

        // Hold the close until the monitors have stopped and LibreHardwareMonitor has released its driver handles.
        e.Cancel = true;
        await _viewModel.DisposeAsync();
        _monitorsStopped = true;
        Close();
    }
}
