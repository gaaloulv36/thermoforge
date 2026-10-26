using System.Text.Json;
using ThermoForge.Core.Processes;

namespace ThermoForge.Core.Reputation;

/// <summary>
/// Remembers VirusTotal and Defender results per exact file (SHA-256), so they survive restarts
/// and keep counting toward the risk score. A result stops applying as soon as the file changes.
/// Thread-safe: read by the polling threads, written after the user asks for a check.
/// </summary>
public sealed class ReputationStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly string? _filePath;
    private readonly FileHashCache _hashes;
    private readonly object _lock = new();
    private readonly Dictionary<string, FileReputation> _bySha = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _shaByPath = new(StringComparer.OrdinalIgnoreCase);

    /// <param name="filePath">Where to persist results; null keeps them in memory (tests).</param>
    public ReputationStore(string? filePath, FileHashCache hashes)
    {
        _filePath = filePath;
        _hashes = hashes;
        foreach (var reputation in Load(filePath))
        {
            _bySha[reputation.Sha256] = reputation;
            _shaByPath[reputation.Path] = reputation.Sha256;
        }
    }

    public static string DefaultPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ThermoForge", "reputation.json");

    public FileHashCache Hashes => _hashes;

    public event EventHandler? Changed;

    public IReadOnlyList<FileReputation> All
    {
        get
        {
            lock (_lock)
                return _bySha.Values.ToList();
        }
    }

    /// <summary>Results for the file at <paramref name="path"/>, if it was checked and hasn't changed since.</summary>
    public FileReputation? For(string? path)
    {
        if (path is null)
            return null;

        string? sha;
        lock (_lock)
        {
            if (!_shaByPath.TryGetValue(path, out sha))
                return null;
        }

        // Only files checked before are hashed here, and the hash is cached per file version.
        if (!string.Equals(_hashes.Sha256(path), sha, StringComparison.OrdinalIgnoreCase))
            return null;
        lock (_lock)
            return _bySha.GetValueOrDefault(sha);
    }

    public FileReputation RecordVirusTotal(string path, string sha256, VirusTotalReport report) =>
        Record(path, sha256, r => r with { VirusTotal = report });

    public FileReputation RecordDefender(string path, string sha256, DefenderScanResult result) =>
        Record(path, sha256, r => r with { Defender = result });

    private FileReputation Record(string path, string sha256, Func<FileReputation, FileReputation> change)
    {
        FileReputation updated;
        lock (_lock)
        {
            var current = _bySha.GetValueOrDefault(sha256) ?? new FileReputation(sha256, path, null, null);
            updated = change(current with { Path = path });
            _bySha[sha256] = updated;
            _shaByPath[path] = sha256;
            Save();
        }
        Changed?.Invoke(this, EventArgs.Empty);
        return updated;
    }

    private void Save()
    {
        if (_filePath is null)
            return;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_filePath)!);
            File.WriteAllText(_filePath, JsonSerializer.Serialize(_bySha.Values.ToList(), JsonOptions));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Results still apply for this session; they just won't survive a restart.
        }
    }

    private static List<FileReputation> Load(string? filePath)
    {
        try
        {
            return filePath is not null && File.Exists(filePath)
                ? JsonSerializer.Deserialize<List<FileReputation>>(File.ReadAllText(filePath)) ?? []
                : [];
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            return [];
        }
    }
}
