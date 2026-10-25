using System.Globalization;
using System.Windows;
using System.Windows.Data;
using TempMonitor.Core.Services;

namespace TempMonitor.UI.Converters;

/// <summary>Maps a <see cref="TemperatureStatus"/> to one of the theme brushes defined in App.xaml.</summary>
public sealed class StatusToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var key = value switch
        {
            TemperatureStatus.Normal => "StatusNormalBrush",
            TemperatureStatus.Warm => "StatusWarmBrush",
            TemperatureStatus.Hot => "StatusHotBrush",
            _ => "TextPrimaryBrush",
        };
        return Application.Current.FindResource(key);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
