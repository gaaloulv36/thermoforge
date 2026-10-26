using System.Globalization;
using System.Net.NetworkInformation;
using CommunityToolkit.Mvvm.ComponentModel;
using ThermoForge.Core.Network;
using ThermoForge.Core.Processes;

namespace ThermoForge.UI.ViewModels;

public sealed partial class ConnectionRowViewModel : ObservableObject
{
    public ConnectionRowViewModel(NetConnection connection, ProcessInfo? process)
    {
        _connection = connection;
        _process = process;
    }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HostText), nameof(StateText), nameof(Findings), nameof(HasFindings),
        nameof(FindingsSummary), nameof(Risk), nameof(Severity), nameof(IsFlagged), nameof(SeverityText), nameof(RiskText))]
    private NetConnection _connection;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Publisher), nameof(SignatureText), nameof(ProcessRiskText), nameof(IsTrusted),
        nameof(Risk), nameof(Severity), nameof(IsFlagged), nameof(SeverityText), nameof(RiskText))]
    private ProcessInfo? _process;

    public RawConnection Raw => Connection.Raw;
    public int Pid => Raw.Pid;
    public string ProcessName => Connection.ProcessName;
    public string? ProcessPath => Connection.ProcessPath;
    public string ProcessText => $"{ProcessName} (PID {Pid})";
    public string PathText => ProcessPath ?? "Hidden by Windows. Run as administrator to see it.";
    public string ProtocolText => Raw.Protocol == NetProtocol.Tcp ? "TCP" : "UDP";
    public bool IsListening => Raw.IsListening;
    public RemoteScope Scope => Connection.Scope;

    /// <summary>Traffic that never leaves the PC: loopback connections and loopback-only listeners.</summary>
    public bool IsThisPc => Scope == RemoteScope.ThisPc
        || (IsListening && System.Net.IPAddress.IsLoopback(Raw.Local.Address));

    public string DirectionText => Connection.Direction switch
    {
        ConnectionDirection.Listening => "Listening",
        ConnectionDirection.Incoming => "In",
        _ => "Out",
    };

    public string LocalText => Raw.Local.ToString();
    public string RemoteText => Raw.Remote?.ToString() ?? "";

    /// <summary>For the list: where it goes, or which port it waits on.</summary>
    public string AddressText => IsListening ? LocalText : RemoteText;

    /// <summary>The address to copy or look up: the other end, or our own when listening.</summary>
    public string Address => (Raw.Remote ?? Raw.Local).Address.ToString();

    public bool CanLookUp => Scope == RemoteScope.Internet;

    public string HostText => Connection.HostName ?? "";

    public string ScopeText => Scope switch
    {
        RemoteScope.ThisPc => "This PC",
        RemoteScope.LocalNetwork => "Local network",
        RemoteScope.Internet => "Internet",
        _ => System.Net.IPAddress.IsLoopback(Raw.Local.Address) ? "This PC only" : "All networks",
    };

    public string StateText => Raw.State switch
    {
        null => "Open",
        TcpState.Listen => "Listening",
        TcpState.Established => "Connected",
        TcpState.SynSent or TcpState.SynReceived => "Connecting",
        TcpState.TimeWait or TcpState.CloseWait or TcpState.FinWait1 or TcpState.FinWait2
            or TcpState.Closing or TcpState.LastAck => "Closing",
        var state => state.ToString()!,
    };

    public string FirstSeenText => $"Seen since {Connection.FirstSeen.ToString("T", CultureInfo.CurrentCulture)}";

    public string Publisher => Process?.File?.Signature.Status switch
    {
        SignatureStatus.Signed => Process.File.Signature.Signer ?? Process.File.Company ?? "Store package",
        SignatureStatus.Unsigned => Process.File.Company is { } company ? $"{company} (unverified)" : "Unsigned",
        SignatureStatus.Invalid => "Invalid signature",
        _ => "",
    };

    public string SignatureText => Process?.File?.Signature switch
    {
        null => "Signature not checked: Windows hides this program's file.",
        { Status: SignatureStatus.Signed } s => $"Signed by {s.Signer ?? "a verified publisher"}",
        { Status: SignatureStatus.Unsigned } => "Not digitally signed",
        { Status: SignatureStatus.Invalid } s => $"Invalid signature: {s.Detail}",
        var s => $"Signature could not be checked: {s.Detail}",
    };

    public IReadOnlyList<ProcessFinding> Findings => Connection.Findings;
    public bool HasFindings => Findings.Count > 0;
    public string FindingsSummary => Findings.Count switch
    {
        0 => "",
        1 => Findings[0].Title,
        _ => $"{Findings.MaxBy(f => f.Severity)!.Title} (+{Findings.Count - 1} more)",
    };

    public bool IsTrusted => Process?.IsTrusted ?? false;

    /// <summary>Risk of this connection alone; the process's overall risk is on the Processes tab.</summary>
    public int Risk => IsTrusted ? 0 : RiskScore.From(Findings);

    public FindingSeverity Severity => RiskScore.Level(Risk);
    public bool IsFlagged => Severity > FindingSeverity.None;
    public string SeverityText => IsTrusted && HasFindings ? "Trusted" : Severity == FindingSeverity.None ? "" : $"{Severity} · {Risk}";
    public string RiskText => IsTrusted
        ? "Trusted by you: findings are shown for reference but don't count."
        : Risk == 0 ? "Nothing suspicious about this connection" : $"Connection risk {Risk}/100 ({Severity})";

    public string ProcessRiskText => Process is null ? ""
        : Process.Risk == 0 ? "The program itself has no risk score."
        : $"The program's overall risk is {Process.Risk}/100 ({Process.Severity}), including this connection.";

    /// <summary>Applies a newer poll, raising change notifications only when something visible changed.</summary>
    public void Update(NetConnection connection, ProcessInfo? process)
    {
        if (connection.Raw != Connection.Raw || connection.HostName != Connection.HostName
            || !connection.Findings.SequenceEqual(Connection.Findings))
            Connection = connection;
        if (process?.Risk != Process?.Risk || process?.IsTrusted != Process?.IsTrusted || process?.File != Process?.File)
            Process = process;
    }
}
