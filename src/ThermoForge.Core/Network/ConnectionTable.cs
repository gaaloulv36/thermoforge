using System.Buffers.Binary;
using System.ComponentModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace ThermoForge.Core.Network;

/// <summary>
/// Reads Windows' TCP and UDP tables with the owning process of each socket, the same data
/// netstat -ano and Resource Monitor show. Works without admin rights.
/// </summary>
public static class ConnectionTable
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;
    private const int UdpTableOwnerPid = 1;
    private const uint ErrorInsufficientBuffer = 122;

    // Row sizes of MIB_TCPROW_OWNER_PID, MIB_TCP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDP6ROW_OWNER_PID.
    private const int Tcp4Row = 24;
    private const int Tcp6Row = 56;
    private const int Udp4Row = 12;
    private const int Udp6Row = 28;

    /// <summary>All sockets except the ones owned by PID 0 (closed connections waiting to time out).</summary>
    public static IReadOnlyList<RawConnection> Read()
    {
        var connections = new List<RawConnection>();
        connections.AddRange(ParseTcp4(ReadTable(tcp: true, AfInet)));
        connections.AddRange(ParseTcp6(ReadTable(tcp: true, AfInet6)));
        connections.AddRange(ParseUdp4(ReadTable(tcp: false, AfInet)));
        connections.AddRange(ParseUdp6(ReadTable(tcp: false, AfInet6)));
        return connections;
    }

    internal static IEnumerable<RawConnection> ParseTcp4(byte[] table) =>
        Rows(table, Tcp4Row).Select(row => new RawConnection(
            NetProtocol.Tcp,
            new IPEndPoint(new IPAddress(row.AsSpan(4, 4)), Port(row[8..])),
            Remote(new IPAddress(row.AsSpan(12, 4)), Port(row[16..]), (TcpState)U32(row)),
            (TcpState)U32(row),
            (int)U32(row[20..])))
            .Where(c => c.Pid != 0)
            .ToList();

    internal static IEnumerable<RawConnection> ParseTcp6(byte[] table) =>
        Rows(table, Tcp6Row).Select(row => new RawConnection(
            NetProtocol.Tcp,
            new IPEndPoint(new IPAddress(row[..16], U32(row[16..])), Port(row[20..])),
            Remote(new IPAddress(row.AsSpan(24, 16), U32(row[40..])), Port(row[44..]), (TcpState)U32(row[48..])),
            (TcpState)U32(row[48..]),
            (int)U32(row[52..])))
            .Where(c => c.Pid != 0)
            .ToList();

    internal static IEnumerable<RawConnection> ParseUdp4(byte[] table) =>
        Rows(table, Udp4Row).Select(row => new RawConnection(
            NetProtocol.Udp,
            new IPEndPoint(new IPAddress(row[..4]), Port(row[4..])),
            null,
            null,
            (int)U32(row[8..])))
            .Where(c => c.Pid != 0)
            .ToList();

    internal static IEnumerable<RawConnection> ParseUdp6(byte[] table) =>
        Rows(table, Udp6Row).Select(row => new RawConnection(
            NetProtocol.Udp,
            new IPEndPoint(new IPAddress(row[..16], U32(row[16..])), Port(row[20..])),
            null,
            null,
            (int)U32(row[24..])))
            .Where(c => c.Pid != 0)
            .ToList();

    private static IPEndPoint? Remote(IPAddress address, int port, TcpState state) =>
        state == TcpState.Listen ? null : new IPEndPoint(address, port);

    /// <summary>The table is a row count followed by fixed-size rows.</summary>
    private static IEnumerable<byte[]> Rows(byte[] table, int rowSize)
    {
        if (table.Length < 4)
            yield break;
        var count = BinaryPrimitives.ReadUInt32LittleEndian(table);
        for (var i = 0; i < count && 4 + (i + 1) * rowSize <= table.Length; i++)
            yield return table.AsSpan(4 + i * rowSize, rowSize).ToArray();
    }

    private static uint U32(ReadOnlySpan<byte> bytes) => BinaryPrimitives.ReadUInt32LittleEndian(bytes);

    /// <summary>Ports are stored in network byte order in the low 16 bits of a DWORD.</summary>
    private static int Port(ReadOnlySpan<byte> bytes) => BinaryPrimitives.ReadUInt16BigEndian(bytes);

    private static byte[] ReadTable(bool tcp, int family)
    {
        var size = 0;
        for (var attempt = 0; attempt < 5; attempt++)
        {
            var buffer = size == 0 ? IntPtr.Zero : Marshal.AllocHGlobal(size);
            try
            {
                var result = tcp
                    ? GetExtendedTcpTable(buffer, ref size, false, family, TcpTableOwnerPidAll, 0)
                    : GetExtendedUdpTable(buffer, ref size, false, family, UdpTableOwnerPid, 0);
                if (result == 0)
                {
                    var table = new byte[size];
                    Marshal.Copy(buffer, table, 0, size);
                    return table;
                }
                if (result != ErrorInsufficientBuffer)
                    throw new Win32Exception((int)result, $"Could not read the {(tcp ? "TCP" : "UDP")} connection table.");
                // The table grew between the size query and the read; try again with the new size.
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(buffer);
            }
        }
        throw new Win32Exception((int)ErrorInsufficientBuffer, "The connection table kept changing size.");
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int family, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetExtendedUdpTable(IntPtr table, ref int size, bool order, int family, int tableClass, uint reserved);

    /// <summary>Classifies the other end of a connection.</summary>
    public static RemoteScope ScopeOf(IPAddress? address)
    {
        if (address is null)
            return RemoteScope.None;
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();
        if (IPAddress.IsLoopback(address))
            return RemoteScope.ThisPc;

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (address.Equals(IPAddress.IPv6Any))
                return RemoteScope.None;
            var first = address.GetAddressBytes()[0];
            return address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast || (first & 0xFE) == 0xFC
                ? RemoteScope.LocalNetwork
                : RemoteScope.Internet;
        }

        var b = address.GetAddressBytes();
        if (b[0] == 0)
            return RemoteScope.None;
        var isPrivate = b[0] == 10
            || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
            || (b[0] == 192 && b[1] == 168)
            || (b[0] == 169 && b[1] == 254)
            || (b[0] == 100 && b[1] >= 64 && b[1] <= 127) // Carrier-grade NAT
            || b[0] >= 224; // Multicast and broadcast
        return isPrivate ? RemoteScope.LocalNetwork : RemoteScope.Internet;
    }
}
