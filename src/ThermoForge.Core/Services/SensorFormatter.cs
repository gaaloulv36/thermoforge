using System.Globalization;
using ThermoForge.Core.Models;

namespace ThermoForge.Core.Services;

public static class SensorFormatter
{
    public const string Missing = "—";

    public static string Format(SensorKind kind, double? value)
    {
        if (value is not double v)
            return Missing;

        var c = CultureInfo.CurrentCulture;
        return kind switch
        {
            SensorKind.Temperature => string.Format(c, "{0:F1} °C", v),
            SensorKind.Load or SensorKind.Level => string.Format(c, "{0:F0} %", v),
            SensorKind.Clock => string.Format(c, "{0:F0} MHz", v),
            SensorKind.Fan => string.Format(c, "{0:F0} RPM", v),
            SensorKind.Power => string.Format(c, "{0:F1} W", v),
            SensorKind.Voltage => string.Format(c, "{0:F3} V", v),
            SensorKind.Data => string.Format(c, "{0:F1} GB", v),
            SensorKind.SmallData => string.Format(c, "{0:F0} MB", v),
            SensorKind.Throughput => FormatThroughput(v, c),
            _ => string.Format(c, "{0:F1}", v),
        };
    }

    private static string FormatThroughput(double bytesPerSecond, CultureInfo c)
    {
        string[] units = ["B/s", "KB/s", "MB/s", "GB/s"];
        var unit = 0;
        while (bytesPerSecond >= 1024 && unit < units.Length - 1)
        {
            bytesPerSecond /= 1024;
            unit++;
        }
        return string.Format(c, "{0:F1} {1}", bytesPerSecond, units[unit]);
    }
}
