using System.Diagnostics;
using TempMonitor.Core.Platform;

namespace TempMonitor.Core.Processes;

/// <summary>
/// Signature verification costs tens of milliseconds per file, so results are cached per
/// path and reused until the file's size or timestamp changes. Not thread-safe; used from
/// the process polling thread only.
/// </summary>
public sealed class FileMetadataCache
{
    private readonly Dictionary<string, Entry> _entries = new(StringComparer.OrdinalIgnoreCase);

    public FileMetadata Get(string path)
    {
        FileInfo file;
        try
        {
            file = new FileInfo(path);
            if (!file.Exists)
                return new FileMetadata(SignatureInfo.Unknown("The file no longer exists on disk."), null, null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return new FileMetadata(SignatureInfo.Unknown(ex.Message), null, null);
        }

        if (_entries.TryGetValue(path, out var cached)
            && cached.LastWriteUtc == file.LastWriteTimeUtc
            && cached.Length == file.Length)
        {
            return cached.Metadata;
        }

        var metadata = Load(path);
        _entries[path] = new Entry(file.LastWriteTimeUtc, file.Length, metadata);
        return metadata;
    }

    private static FileMetadata Load(string path)
    {
        var signature = AuthenticodeVerifier.Verify(path);
        try
        {
            var version = FileVersionInfo.GetVersionInfo(path);
            return new FileMetadata(signature, NullIfBlank(version.FileDescription), NullIfBlank(version.CompanyName));
        }
        catch (FileNotFoundException)
        {
            return new FileMetadata(signature, null, null);
        }
    }

    private static string? NullIfBlank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private sealed record Entry(DateTime LastWriteUtc, long Length, FileMetadata Metadata);
}
