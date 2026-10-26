using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace ThermoForge.Core.Network;

/// <summary>
/// Reverse DNS names for remote addresses, looked up in the background so polling never
/// waits on the network. The first request for an address returns null; later ones get the name.
/// Thread-safe.
/// </summary>
public sealed class HostNameCache
{
    private const int MaxEntries = 4096;
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);

    private readonly ConcurrentDictionary<IPAddress, string?> _names = new();
    private readonly ConcurrentDictionary<IPAddress, byte> _pending = new();
    private readonly SemaphoreSlim _slots = new(4, 4);

    public string? Get(IPAddress address)
    {
        if (_names.TryGetValue(address, out var name))
            return name;
        if (_pending.TryAdd(address, 0))
            _ = LookUpAsync(address);
        return null;
    }

    private async Task LookUpAsync(IPAddress address)
    {
        string? name = null;
        await _slots.WaitAsync();
        try
        {
            var lookup = Dns.GetHostEntryAsync(address);
            // After a timeout the lookup still finishes (often failing) later; observe it so the
            // failure isn't reported as an unhandled task exception.
            _ = lookup.ContinueWith(t => t.Exception, TaskContinuationOptions.OnlyOnFaulted);
            var entry = await lookup.WaitAsync(Timeout);
            if (!string.IsNullOrEmpty(entry.HostName) && entry.HostName != address.ToString())
                name = entry.HostName;
        }
        catch (Exception ex) when (ex is SocketException or TimeoutException or ArgumentException)
        {
            // Most addresses have no reverse name; remember that so we don't ask again.
        }
        finally
        {
            _slots.Release();
        }

        if (_names.Count >= MaxEntries)
            _names.Clear();
        _names[address] = name;
        _pending.TryRemove(address, out _);
    }
}
