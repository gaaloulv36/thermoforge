using System.Globalization;
using System.Windows.Data;

namespace ThermoForge.UI.Converters;

/// <summary>Upper-cases text, for the website-style monospace column headers.</summary>
public sealed class UpperCaseConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value?.ToString()?.ToUpper(culture) ?? "";

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
