using System.Security.Cryptography;

namespace ThermoForge.Core.Processes;

/// <summary>
/// SHA-256 of files, cached per file version (size and timestamp) so files that are checked
/// every poll are only read once. Thread-safe.
/// </summary>
public sealed class FileHashCache
{
    private readonly object _lock = new();
    private readonly Dictionary<string, Entry> _entries = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Upper-case hex SHA-256, or null when the file can't be read.</summary>
    public string? Sha256(string path)
    {
        try
        {
            var file = new FileInfo(path);
            if (!file.Exists)
                return null;

            lock (_lock)
            {
                if (_entries.TryGetValue(path, out var cached)
                    && cached.LastWriteUtc == file.LastWriteTimeUtc && cached.Length == file.Length)
                    return cached.Sha256;
            }

            using var stream = File.OpenRead(path);
            var hash = Convert.ToHexString(SHA256.HashData(stream));
            lock (_lock)
                _entries[path] = new Entry(file.LastWriteTimeUtc, file.Length, hash);
            return hash;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return null;
        }
    }

    private sealed record Entry(DateTime LastWriteUtc, long Length, string Sha256);
}
