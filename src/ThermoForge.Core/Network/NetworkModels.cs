using System.Net;
using System.Net.NetworkInformation;
using ThermoForge.Core.Processes;

namespace ThermoForge.Core.Network;

public enum NetProtocol
{
    Tcp,
    Udp,
}

/// <summary>A socket as reported by Windows' connection table, before any analysis.</summary>
/// <param name="Remote">Null for UDP and for listening TCP sockets.</param>
/// <param name="State">Null for UDP, which has no connection state.</param>
public sealed record RawConnection(NetProtocol Protocol, IPEndPoint Local, IPEndPoint? Remote, TcpState? State, int Pid)
{
    /// <summary>Waiting for others to connect: a listening TCP socket, or any bound UDP socket.</summary>
    public bool IsListening => Protocol == NetProtocol.Udp || State == TcpState.Listen;
}

/// <summary>Where the other end of a connection is.</summary>
public enum RemoteScope
{
    /// <summary>Listening sockets: no other end yet.</summary>
    None,

    /// <summary>Another program on this PC (127.0.0.1, ::1).</summary>
    ThisPc,

    /// <summary>Private, link-local and multicast addresses: the home or office network.</summary>
    LocalNetwork,

    Internet,
}

public enum ConnectionDirection
{
    Listening,

    /// <summary>This PC opened the connection.</summary>
    Outgoing,

    /// <summary>Someone connected to a port this program listens on.</summary>
    Incoming,
}

/// <param name="HostName">Reverse DNS name of the remote address, once looked up; null when unknown.</param>
/// <param name="Findings">Suspicious traits of this connection; they also count toward the process's risk.</param>
public sealed record NetConnection(
    RawConnection Raw,
    string ProcessName,
    string? ProcessPath,
    ConnectionDirection Direction,
    RemoteScope Scope,
    string? HostName,
    DateTime FirstSeen,
    IReadOnlyList<ProcessFinding> Findings);
