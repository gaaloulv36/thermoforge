using System.Security.Cryptography;
using System.Text.Json;

namespace ThermoForge.Core.Processes;

/// <summary>
/// Programs the user has marked as known-good. Trust is tied to the exact file contents
/// (SHA-256), so if the file is replaced or tampered with, it is checked again.
/// Thread-safe: read by the polling thread, changed from the UI.
/// </summary>
public sealed class TrustStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly string _filePath;
    private readonly object _lock = new();
    private readonly Dictionary<string, TrustedProgram> _byPath = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, HashEntry> _hashes = new(StringComparer.OrdinalIgnoreCase);

    public TrustStore(string filePath)
    {
        _filePath = filePath;
        foreach (var program in Load(filePath))
            _byPath[program.Path] = program;
    }

    public static string DefaultPath { get; } = System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ThermoForge", "trusted.json");

    public event EventHandler? Changed;

    public IReadOnlyList<TrustedProgram> Programs
    {
        get
        {
            lock (_lock)
                return _byPath.Values.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToList();
        }
    }

    public bool IsTrusted(string? path)
    {
        if (path is null)
            return false;

        TrustedProgram? program;
        lock (_lock)
        {
            if (!_byPath.TryGetValue(path, out program))
                return false;
        }
        return string.Equals(HashOf(path), program.Sha256, StringComparison.OrdinalIgnoreCase);
    }

    /// <exception cref="IOException">The file can't be read or the list can't be saved.</exception>
    public void Trust(string path, string name, string? publisher)
    {
        var hash = HashOf(path) ?? throw new IOException($"Could not read {path}.");
        lock (_lock)
        {
            _byPath[path] = new TrustedProgram(path, name, publisher, hash, DateTime.Now);
            Save();
        }
        Changed?.Invoke(this, EventArgs.Empty);
    }

    public void Remove(string path)
    {
        lock (_lock)
        {
            if (!_byPath.Remove(path))
                return;
            Save();
        }
        Changed?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>Hashes are cached per file version so trusted programs aren't re-read every poll.</summary>
    private string? HashOf(string path)
    {
        try
        {
            var file = new FileInfo(path);
            if (!file.Exists)
                return null;

            lock (_lock)
            {
                if (_hashes.TryGetValue(path, out var cached)
                    && cached.LastWriteUtc == file.LastWriteTimeUtc && cached.Length == file.Length)
                    return cached.Sha256;
            }

            using var stream = File.OpenRead(path);
            var hash = Convert.ToHexString(SHA256.HashData(stream));
            lock (_lock)
                _hashes[path] = new HashEntry(file.LastWriteTimeUtc, file.Length, hash);
            return hash;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private void Save()
    {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(_filePath)!);
        File.WriteAllText(_filePath, JsonSerializer.Serialize(_byPath.Values.ToList(), JsonOptions));
    }

    private static List<TrustedProgram> Load(string filePath)
    {
        try
        {
            return File.Exists(filePath)
                ? JsonSerializer.Deserialize<List<TrustedProgram>>(File.ReadAllText(filePath)) ?? []
                : [];
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            // A corrupt list must not stop the app; the user can trust programs again.
            return [];
        }
    }

    private sealed record HashEntry(DateTime LastWriteUtc, long Length, string Sha256);
}

public sealed record TrustedProgram(string Path, string Name, string? Publisher, string Sha256, DateTime TrustedAt);
