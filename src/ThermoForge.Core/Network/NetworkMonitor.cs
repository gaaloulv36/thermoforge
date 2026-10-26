using System.Net;
using ThermoForge.Core.Processes;

namespace ThermoForge.Core.Network;

/// <summary>
/// Reads the connection table on every process poll, ties each socket to its process, and runs
/// it through <see cref="NetworkAnalyzer"/> and <see cref="BeaconDetector"/>. Findings are also
/// returned per process so they count toward its risk score. Call <see cref="Observe"/> from one thread.
/// </summary>
public sealed class NetworkMonitor
{
    private readonly Func<IReadOnlyList<RawConnection>> _read;
    private readonly Func<IPAddress, string?> _hostName;
    private readonly NetworkAnalyzer _analyzer = new();
    private readonly BeaconDetector _beacons = new();
    private Dictionary<ConnectionKey, DateTime> _firstSeenUtc = new();
    private bool _polled;

    /// <param name="read">The connection table; defaults to Windows' own.</param>
    /// <param name="hostName">Reverse DNS lookup that returns null until it knows; defaults to a background cache.</param>
    public NetworkMonitor(Func<IReadOnlyList<RawConnection>>? read = null, Func<IPAddress, string?>? hostName = null)
    {
        _read = read ?? ConnectionTable.Read;
        _hostName = hostName ?? new HostNameCache().Get;
    }

    /// <summary>What the process monitor knows about a PID.</summary>
    public readonly record struct Owner(RawProcess Process, SignatureInfo? Signature);

    public sealed record Observation(
        IReadOnlyList<NetConnection> Connections,
        IReadOnlyDictionary<int, IReadOnlyList<ProcessFinding>> FindingsByPid);

    public Observation Observe(IReadOnlyDictionary<int, Owner> owners, DateTime nowUtc)
    {
        var raws = _read();
        var listeningPorts = raws
            .Where(r => r.Protocol == NetProtocol.Tcp && r.State == System.Net.NetworkInformation.TcpState.Listen)
            .Select(r => (r.Pid, r.Local.Port))
            .ToHashSet();

        var firstSeen = new Dictionary<ConnectionKey, DateTime>(raws.Count);
        var connections = new List<NetConnection>(raws.Count);
        var findingsByPid = new Dictionary<int, List<ProcessFinding>>();

        foreach (var raw in raws)
        {
            var key = new ConnectionKey(raw.Protocol, raw.Local, raw.Remote, raw.Pid);
            var isNew = !_firstSeenUtc.TryGetValue(key, out var first);
            if (isNew)
                first = nowUtc;
            if (!firstSeen.TryAdd(key, first))
                continue; // Windows can list a socket twice while it changes state.

            var hasOwner = owners.TryGetValue(raw.Pid, out var owner);
            var name = hasOwner ? owner.Process.Name : raw.Pid == 4 ? "System" : $"PID {raw.Pid}";
            var direction = raw.IsListening ? ConnectionDirection.Listening
                : listeningPorts.Contains((raw.Pid, raw.Local.Port)) ? ConnectionDirection.Incoming
                : ConnectionDirection.Outgoing;
            var scope = raw.IsListening ? RemoteScope.None : ConnectionTable.ScopeOf(raw.Remote?.Address);
            var host = scope is RemoteScope.Internet or RemoteScope.LocalNetwork ? _hostName(raw.Remote!.Address) : null;
            var signature = owner.Signature?.Status;

            // Don't report ourselves, as on the Processes tab: a dev build is unsigned.
            List<ProcessFinding> findings = raw.Pid == Environment.ProcessId
                ? []
                : _analyzer.Analyze(raw, direction, scope, host, name, signature).ToList();

            if (hasOwner && direction == ConnectionDirection.Outgoing && scope == RemoteScope.Internet && raw.Protocol == NetProtocol.Tcp)
            {
                var beaconKey = new BeaconDetector.Key(raw.Pid, owner.Process.StartTime, raw.Remote!.Address);
                // On the first poll every connection looks new; it says nothing about when it was opened.
                if (isNew && _polled)
                    _beacons.Record(beaconKey, nowUtc);
                if (raw.Pid != Environment.ProcessId && _beacons.Interval(beaconKey) is { } interval
                    && NetworkAnalyzer.Beacon(signature, interval, host ?? raw.Remote.Address.ToString()) is { } beacon)
                    findings.Add(beacon);
            }

            connections.Add(new NetConnection(raw, name, hasOwner ? owner.Process.Path : null, direction, scope, host,
                first.ToLocalTime(), findings));
            if (findings.Count > 0)
                (findingsByPid.TryGetValue(raw.Pid, out var list) ? list : findingsByPid[raw.Pid] = []).AddRange(findings);
        }

        _firstSeenUtc = firstSeen;
        _beacons.Prune(nowUtc);
        _polled = true;

        // A program with fifty connections to the internet still has one "talks to the internet" finding.
        return new Observation(connections, findingsByPid.ToDictionary(
            p => p.Key,
            p => (IReadOnlyList<ProcessFinding>)p.Value.GroupBy(f => f.Title).Select(g => g.MaxBy(f => f.Severity)!).ToList()));
    }

    private readonly record struct ConnectionKey(NetProtocol Protocol, IPEndPoint Local, IPEndPoint? Remote, int Pid);
}
