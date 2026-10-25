using System.Globalization;
using System.Management;
using System.Text.RegularExpressions;

namespace ThermoForge.Core.Processes;

/// <summary>
/// Per-process GPU use from the "GPU Engine" performance counters (what Task Manager shows).
/// Each process has one counter instance per GPU engine; like Task Manager, a process's
/// figure is its busiest engine type. Returns an empty map when the counters are unavailable,
/// and while they warm up: the first query takes several seconds, so it runs in the background
/// rather than delaying the first process snapshot.
/// </summary>
public sealed partial class GpuUsageReader : IDisposable
{
    private const string Query =
        "SELECT Name, UtilizationPercentage FROM Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine";

    private readonly ManagementObjectSearcher _searcher = new("root\\CIMV2", Query);
    private readonly Task _warmUp;
    private volatile bool _unavailable;

    public GpuUsageReader()
    {
        _warmUp = Task.Run(() =>
        {
            try
            {
                // Results stream in lazily; enumerate them so the query really runs.
                using var results = _searcher.Get();
                foreach (var obj in results)
                    obj.Dispose();
            }
            catch (ManagementException)
            {
                _unavailable = true;
            }
        });
    }

    public IReadOnlyDictionary<int, double> Read()
    {
        if (_unavailable || !_warmUp.IsCompleted)
            return new Dictionary<int, double>();

        var samples = new List<(string Name, double Percent)>();
        try
        {
            using var results = _searcher.Get();
            foreach (var obj in results)
            {
                using (obj)
                    samples.Add(((obj["Name"] as string) ?? "", Convert.ToDouble(obj["UtilizationPercentage"], CultureInfo.InvariantCulture)));
            }
        }
        catch (ManagementException)
        {
            // Older drivers / VMs without GPU counters: stop asking every poll.
            _unavailable = true;
        }
        return Aggregate(samples);
    }

    public void Dispose() => _searcher.Dispose();

    /// <summary>Sums each process's engines per engine type, then takes the busiest type.</summary>
    internal static Dictionary<int, double> Aggregate(IEnumerable<(string Name, double Percent)> samples) =>
        samples
            .Select(s => (Match: InstanceName().Match(s.Name), s.Percent))
            .Where(s => s.Match.Success)
            .GroupBy(s => (Pid: int.Parse(s.Match.Groups["pid"].Value, CultureInfo.InvariantCulture),
                           Engine: s.Match.Groups["engine"].Value.ToUpperInvariant()))
            .GroupBy(g => g.Key.Pid, g => g.Sum(s => s.Percent))
            .ToDictionary(g => g.Key, g => Math.Min(100, g.Max()));

    // e.g. "pid_1234_luid_0x00000000_0x0000D1A3_phys_0_eng_0_engtype_3D"
    [GeneratedRegex(@"^pid_(?<pid>\d+)_.*_engtype_(?<engine>.+)$", RegexOptions.IgnoreCase)]
    private static partial Regex InstanceName();
}
