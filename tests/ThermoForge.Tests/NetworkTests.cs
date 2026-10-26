using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using ThermoForge.Core.Network;
using ThermoForge.Core.Processes;

namespace ThermoForge.Tests;

public class ConnectionTableTests
{
    /// <summary>A table as GetExtendedTcpTable/GetExtendedUdpTable return it: count, then rows.</summary>
    private static byte[] Table(params byte[][] rows) =>
    [
        .. BitConverter.GetBytes((uint)rows.Length),
        .. rows.SelectMany(r => r),
    ];

    private static byte[] U32(uint value) => BitConverter.GetBytes(value);

    private static byte[] Port(int port)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, (ushort)port);
        return bytes;
    }

    [Fact]
    public void ParsesTcp4Rows_AndSkipsPidZero()
    {
        byte[] established = [.. U32(5), 192, 168, 1, 20, .. Port(51000), 93, 184, 216, 34, .. Port(443), .. U32(1234)];
        byte[] listening = [.. U32(2), 0, 0, 0, 0, .. Port(8080), 0, 0, 0, 0, .. Port(0), .. U32(99)];
        byte[] timeWait = [.. U32(11), 10, 0, 0, 1, .. Port(50000), 10, 0, 0, 2, .. Port(80), .. U32(0)];

        var rows = ConnectionTable.ParseTcp4(Table(established, listening, timeWait)).ToList();

        Assert.Equal(2, rows.Count);
        Assert.Equal(new RawConnection(NetProtocol.Tcp, new(IPAddress.Parse("192.168.1.20"), 51000),
            new(IPAddress.Parse("93.184.216.34"), 443), TcpState.Established, 1234), rows[0]);
        Assert.True(rows[1].IsListening);
        Assert.Null(rows[1].Remote);
        Assert.Equal(8080, rows[1].Local.Port);
    }

    [Fact]
    public void ParsesTcp6AndUdpRows()
    {
        var v6 = IPAddress.Parse("2001:db8::1").GetAddressBytes();
        byte[] tcp6 = [.. v6, .. U32(0), .. Port(52000), .. v6, .. U32(0), .. Port(443), .. U32(5), .. U32(7)];
        byte[] udp4 = [127, 0, 0, 1, .. Port(53), .. U32(8)];
        byte[] udp6 = [.. new byte[16], .. U32(0), .. Port(5353), .. U32(9)];

        var tcp = Assert.Single(ConnectionTable.ParseTcp6(Table(tcp6)));
        Assert.Equal(new IPEndPoint(IPAddress.Parse("2001:db8::1"), 443), tcp.Remote);
        Assert.Equal(7, tcp.Pid);

        var udp = Assert.Single(ConnectionTable.ParseUdp4(Table(udp4)));
        Assert.Equal(new IPEndPoint(IPAddress.Loopback, 53), udp.Local);
        Assert.True(udp.IsListening);

        Assert.Equal(new IPEndPoint(IPAddress.IPv6Any, 5353), Assert.Single(ConnectionTable.ParseUdp6(Table(udp6))).Local);
    }

    [Fact]
    public void ReadsThisPcsRealTable()
    {
        // Any Windows PC has listening sockets (RPC on 135 at least).
        Assert.Contains(ConnectionTable.Read(), c => c.IsListening);
    }

    [Theory]
    [InlineData("127.0.0.1", RemoteScope.ThisPc)]
    [InlineData("::1", RemoteScope.ThisPc)]
    [InlineData("192.168.1.1", RemoteScope.LocalNetwork)]
    [InlineData("10.20.30.40", RemoteScope.LocalNetwork)]
    [InlineData("172.20.0.5", RemoteScope.LocalNetwork)]
    [InlineData("172.32.0.5", RemoteScope.Internet)]
    [InlineData("169.254.10.10", RemoteScope.LocalNetwork)]
    [InlineData("100.100.1.1", RemoteScope.LocalNetwork)]
    [InlineData("239.255.255.250", RemoteScope.LocalNetwork)]
    [InlineData("fe80::1", RemoteScope.LocalNetwork)]
    [InlineData("fd00::1", RemoteScope.LocalNetwork)]
    [InlineData("8.8.8.8", RemoteScope.Internet)]
    [InlineData("2606:4700::1111", RemoteScope.Internet)]
    [InlineData("::ffff:192.168.0.1", RemoteScope.LocalNetwork)]
    [InlineData("::ffff:1.1.1.1", RemoteScope.Internet)]
    [InlineData("0.0.0.0", RemoteScope.None)]
    public void ClassifiesRemoteAddresses(string address, RemoteScope scope) =>
        Assert.Equal(scope, ConnectionTable.ScopeOf(IPAddress.Parse(address)));
}

public class NetworkAnalyzerTests
{
    private static readonly NetworkAnalyzer Analyzer = new();

    private static RawConnection Out(string remote, int port) =>
        new(NetProtocol.Tcp, new(IPAddress.Parse("192.168.1.20"), 50000), new(IPAddress.Parse(remote), port), TcpState.Established, 10);

    private static IReadOnlyList<ProcessFinding> Analyze(
        RawConnection c, string process = "app.exe", SignatureStatus? signature = SignatureStatus.Signed,
        ConnectionDirection direction = ConnectionDirection.Outgoing, string? host = null) =>
        Analyzer.Analyze(c, direction, ConnectionTable.ScopeOf(c.Remote?.Address), host, process, signature);

    [Fact]
    public void SignedProgramOnHttps_IsClean() =>
        Assert.Empty(Analyze(Out("93.184.216.34", 443)));

    [Theory]
    [InlineData("powershell.exe", FindingSeverity.Medium)]
    [InlineData("mshta.exe", FindingSeverity.High)]
    [InlineData("certutil.exe", FindingSeverity.High)]
    public void BuiltInToolsOnTheInternet_AreFlagged(string process, FindingSeverity severity)
    {
        var finding = Assert.Single(Analyze(Out("93.184.216.34", 443), process));
        Assert.Equal(severity, finding.Severity);
        Assert.Contains("connects to the internet", finding.Title);
    }

    [Fact]
    public void BuiltInToolsOnTheLocalNetwork_AreNotFlagged() =>
        Assert.Empty(Analyze(Out("192.168.1.5", 445), "powershell.exe"));

    [Theory]
    [InlineData(4444, "hacking tools")]
    [InlineData(3333, "mining pool port")]
    [InlineData(9001, "Tor")]
    [InlineData(6667, "IRC")]
    public void SuspiciousRemotePorts_AreFlagged(int port, string title) =>
        Assert.Contains(Analyze(Out("93.184.216.34", port)), f => f.Title.Contains(title));

    [Fact]
    public void UnsignedProgramOnTheInternet_IsLow()
    {
        var finding = Assert.Single(Analyze(Out("93.184.216.34", 443), signature: SignatureStatus.Unsigned));
        Assert.Equal(FindingSeverity.Low, finding.Severity);
    }

    [Fact]
    public void UnsignedListenerOnAllInterfaces_IsLow_ButLoopbackIsFine()
    {
        var any = new RawConnection(NetProtocol.Tcp, new(IPAddress.Any, 6379), null, TcpState.Listen, 10);
        var loopback = any with { Local = new(IPAddress.Loopback, 6379) };

        Assert.Equal(FindingSeverity.Low, Assert.Single(Analyze(any, signature: SignatureStatus.Unsigned, direction: ConnectionDirection.Listening)).Severity);
        Assert.Empty(Analyze(loopback, signature: SignatureStatus.Unsigned, direction: ConnectionDirection.Listening));
        Assert.Empty(Analyze(any, signature: SignatureStatus.Signed, direction: ConnectionDirection.Listening));
    }

    [Fact]
    public void UnsignedProgramAcceptingInternetConnections_IsMedium() =>
        Assert.Contains(Analyze(Out("93.184.216.34", 51515), signature: SignatureStatus.Unsigned, direction: ConnectionDirection.Incoming),
            f => f.Severity == FindingSeverity.Medium && f.Title == "Accepted a connection from the internet");

    [Theory]
    [InlineData("pool.supportxmr.com", true)]
    [InlineData("xmr-eu1.nanopool.org", true)]
    [InlineData("eu.mining-pool.example", true)]
    [InlineData("0.pool.ntp.org", false)]
    [InlineData("lhr25s34-in-f14.1e100.net", false)]
    public void MiningPoolHostNames_AreFlagged(string host, bool flagged) =>
        Assert.Equal(flagged, Analyze(Out("93.184.216.34", 443), host: host).Any(f => f.Title == "Connects to a crypto-mining pool"));

    [Fact]
    public void Beacon_IgnoresSignedPrograms_AndRatesUnsignedHigher()
    {
        Assert.Null(NetworkAnalyzer.Beacon(SignatureStatus.Signed, TimeSpan.FromSeconds(30), "x"));
        Assert.Equal(FindingSeverity.Medium, NetworkAnalyzer.Beacon(SignatureStatus.Unsigned, TimeSpan.FromSeconds(30), "x")!.Severity);
        Assert.Equal(FindingSeverity.Low, NetworkAnalyzer.Beacon(null, TimeSpan.FromSeconds(30), "x")!.Severity);
    }
}

public class BeaconDetectorTests
{
    private static readonly DateTime T0 = new(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
    private static readonly BeaconDetector.Key Key = new(42, T0, IPAddress.Parse("93.184.216.34"));

    private static BeaconDetector With(params double[] seconds)
    {
        var detector = new BeaconDetector();
        foreach (var s in seconds)
            detector.Record(Key, T0.AddSeconds(s));
        return detector;
    }

    [Fact]
    public void SteadyRhythm_IsDetected_DespitePollJitter() =>
        Assert.Equal(TimeSpan.FromSeconds(60), With(0, 60, 123, 180, 240, 303, 360).Interval(Key));

    [Fact]
    public void TooFewConnections_AreNotABeacon() =>
        Assert.Null(With(0, 60, 120, 180, 240).Interval(Key));

    [Fact]
    public void IrregularConnections_AreNotABeacon() =>
        Assert.Null(With(0, 20, 130, 150, 400, 420, 700).Interval(Key));

    [Fact]
    public void FastChatter_IsNotABeacon() =>
        Assert.Null(With(0, 3, 6, 9, 12, 15, 18).Interval(Key));

    [Fact]
    public void ParallelConnectionsInOnePoll_CountOnce() =>
        Assert.Null(With(0, 0, 0, 60, 60, 120).Interval(Key));

    [Fact]
    public void OldAddresses_ArePruned()
    {
        var detector = With(0, 60, 120, 180, 240, 300);
        detector.Prune(T0.AddHours(2));
        Assert.Null(detector.Interval(Key));
    }
}

public class NetworkMonitorTests
{
    private static readonly DateTime T0 = new(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
    private static readonly RawProcess Agent = new(10, 1, "agent.exe", @"C:\Tools\agent.exe", null, T0);

    private static readonly Dictionary<int, NetworkMonitor.Owner> Owners = new()
    {
        [10] = new(Agent, new SignatureInfo(SignatureStatus.Unsigned, null, null)),
    };

    private List<RawConnection> _table = [];

    private NetworkMonitor Monitor(Func<IPAddress, string?>? hostName = null) => new(() => _table, hostName ?? (_ => null));

    private static RawConnection Tcp(int localPort, string remote, int remotePort, int pid = 10) =>
        new(NetProtocol.Tcp, new(IPAddress.Parse("192.168.1.20"), localPort), new(IPAddress.Parse(remote), remotePort), TcpState.Established, pid);

    [Fact]
    public void TiesConnectionsToProcesses_AndMergesFindingsPerProcess()
    {
        _table = [Tcp(50001, "93.184.216.34", 443), Tcp(50002, "93.184.216.35", 443), Tcp(50003, "8.8.8.8", 443, pid: 77)];

        var result = Monitor().Observe(Owners, T0);

        Assert.Equal(3, result.Connections.Count);
        Assert.Equal("agent.exe", result.Connections[0].ProcessName);
        Assert.Equal(@"C:\Tools\agent.exe", result.Connections[0].ProcessPath);
        Assert.Equal("PID 77", result.Connections[2].ProcessName);
        // Two connections, one "talks to the internet" finding for the process.
        Assert.Single(result.FindingsByPid[10]);
        Assert.False(result.FindingsByPid.ContainsKey(77));
    }

    [Fact]
    public void ConnectionsToAListeningPort_AreIncoming()
    {
        _table =
        [
            new(NetProtocol.Tcp, new(IPAddress.Any, 8080), null, TcpState.Listen, 10),
            Tcp(8080, "93.184.216.34", 51515),
            Tcp(50001, "93.184.216.34", 443),
        ];

        var result = Monitor().Observe(Owners, T0);

        Assert.Equal(
            [ConnectionDirection.Listening, ConnectionDirection.Incoming, ConnectionDirection.Outgoing],
            result.Connections.Select(c => c.Direction));
        Assert.Contains(result.FindingsByPid[10], f => f.Title == "Accepted a connection from the internet");
    }

    [Fact]
    public void FirstSeen_IsKeptAcrossPolls_AndStateChangesKeepTheSameConnection()
    {
        var monitor = Monitor();
        _table = [Tcp(50001, "93.184.216.34", 443) with { State = TcpState.SynSent }];
        monitor.Observe(Owners, T0);

        _table = [Tcp(50001, "93.184.216.34", 443)];
        var later = monitor.Observe(Owners, T0.AddSeconds(3));

        Assert.Equal(T0.ToLocalTime(), Assert.Single(later.Connections).FirstSeen);
    }

    [Fact]
    public void ResolvesHostNames_OnlyForRemoteAddresses()
    {
        var asked = new List<IPAddress>();
        _table =
        [
            Tcp(50001, "93.184.216.34", 443),
            Tcp(50002, "127.0.0.1", 5432),
            new(NetProtocol.Tcp, new(IPAddress.Any, 8080), null, TcpState.Listen, 10),
        ];

        var result = Monitor(ip => { asked.Add(ip); return "example.com"; }).Observe(Owners, T0);

        Assert.Equal([IPAddress.Parse("93.184.216.34")], asked);
        Assert.Equal("example.com", result.Connections[0].HostName);
        Assert.Null(result.Connections[1].HostName);
    }

    [Fact]
    public void ANewConnectionEveryMinute_IsReportedAsBeaconing()
    {
        var monitor = Monitor();
        _table = [];
        monitor.Observe(Owners, T0);

        NetworkMonitor.Observation result = null!;
        for (var i = 0; i < BeaconDetector.MinConnections; i++)
        {
            // Each check-in is a fresh connection (new local port), alive for one poll.
            _table = [Tcp(50000 + i, "203.0.113.9", 8443)];
            result = monitor.Observe(Owners, T0.AddMinutes(i + 1));
            _table = [];
            monitor.Observe(Owners, T0.AddMinutes(i + 1).AddSeconds(3));
        }

        var beacon = Assert.Single(result.FindingsByPid[10], f => f.Title == "Contacts the same server at regular intervals");
        Assert.Equal(FindingSeverity.Medium, beacon.Severity);
        Assert.Contains("1 min", beacon.Detail);
    }

    [Fact]
    public void ConnectionsOpenAtStartup_DoNotCountAsCheckIns()
    {
        var monitor = Monitor();
        _table = [Tcp(50000, "203.0.113.9", 8443)];
        monitor.Observe(Owners, T0);

        for (var i = 1; i < BeaconDetector.MinConnections; i++)
        {
            _table = [Tcp(50000 + i, "203.0.113.9", 8443)];
            var result = monitor.Observe(Owners, T0.AddMinutes(i));
            Assert.DoesNotContain(result.FindingsByPid[10], f => f.Title.Contains("regular intervals"));
        }
    }
}
