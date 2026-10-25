using System.Globalization;
using System.Windows;
using System.Windows.Data;
using TempMonitor.Core.Processes;

namespace TempMonitor.UI.Converters;

/// <summary>Maps a <see cref="FindingSeverity"/> to one of the theme brushes defined in App.xaml.</summary>
public sealed class SeverityToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var key = value switch
        {
            FindingSeverity.High => "StatusHotBrush",
            FindingSeverity.Medium => "StatusWarmBrush",
            FindingSeverity.Low => "SeverityLowBrush",
            _ => "TextPrimaryBrush",
        };
        return Application.Current.FindResource(key);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
