using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace TempMonitor.UI.Converters;

/// <summary>
/// Visible for true, non-zero numbers and non-null objects; collapsed otherwise.
/// Pass ConverterParameter="Invert" to flip.
/// </summary>
public sealed class VisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var visible = value switch
        {
            bool b => b,
            int i => i != 0,
            null => false,
            _ => true,
        };
        if (parameter is "Invert")
            visible = !visible;
        return visible ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
