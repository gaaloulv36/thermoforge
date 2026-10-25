using ThermoForge.Core.Models;

namespace ThermoForge.Core.Services;

public readonly record struct SensorStats(double Min, double Max);

/// <summary>
/// Keeps the most recent <c>capacity</c> values per sensor for charting, plus the
/// session min/max. Not thread-safe: add and read from the same (UI) thread.
/// </summary>
public sealed class SensorHistory
{
    private readonly int _capacity;
    private readonly Dictionary<string, Series> _series = new();

    public SensorHistory(int capacity)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
        _capacity = capacity;
    }

    public void Add(SensorSnapshot snapshot)
    {
        foreach (var reading in snapshot.Readings)
        {
            if (!_series.TryGetValue(reading.Id, out var series))
            {
                series = new Series(_capacity);
                _series.Add(reading.Id, series);
            }
            series.Add(snapshot.Timestamp, reading.Value);
        }
    }

    public SensorStats? GetStats(string id) =>
        _series.TryGetValue(id, out var s) ? new SensorStats(s.Min, s.Max) : null;

    /// <summary>Returns the buffered points for a sensor in chronological order.</summary>
    public (DateTime[] Times, double[] Values) GetSeries(string id) =>
        _series.TryGetValue(id, out var s) ? s.ToArrays() : ([], []);

    private sealed class Series(int capacity)
    {
        private readonly DateTime[] _times = new DateTime[capacity];
        private readonly double[] _values = new double[capacity];
        private int _start;
        private int _count;

        public double Min { get; private set; } = double.MaxValue;
        public double Max { get; private set; } = double.MinValue;

        public void Add(DateTime time, double value)
        {
            var index = (_start + _count) % capacity;
            _times[index] = time;
            _values[index] = value;
            if (_count < capacity)
                _count++;
            else
                _start = (_start + 1) % capacity;

            Min = Math.Min(Min, value);
            Max = Math.Max(Max, value);
        }

        public (DateTime[], double[]) ToArrays()
        {
            var times = new DateTime[_count];
            var values = new double[_count];
            for (var i = 0; i < _count; i++)
            {
                var index = (_start + i) % capacity;
                times[i] = _times[index];
                values[i] = _values[index];
            }
            return (times, values);
        }
    }
}
