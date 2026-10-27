using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using ThermoForge.Core.Platform;
using ThermoForge.Core.Processes;

namespace ThermoForge.Core.Updates;

/// <summary>An update check or download failed for a reason worth showing the user.</summary>
public sealed class UpdateException(string message, Exception? inner = null) : Exception(message, inner);

public sealed record ReleaseAsset(string Name, Uri DownloadUrl, long Size);

/// <param name="Notes">The release description (Markdown) from GitHub.</param>
/// <param name="Checksums">SHA256SUMS.txt; the download is refused without it.</param>
public sealed record AvailableUpdate(
    Version Version,
    string Title,
    string Notes,
    Uri Page,
    DateTime? Published,
    ReleaseAsset Installer,
    ReleaseAsset? Checksums);

/// <summary>
/// Looks for a newer ThermoForge on the GitHub Releases page and downloads its installer. A
/// download is only handed over if it matches the release's SHA256SUMS.txt and, when this copy
/// is code-signed, carries the same publisher's signature. Thread-safe.
/// </summary>
public sealed class UpdateChecker
{
    public const string Repository = "gaaloulv36/thermoforge";
    public static readonly Uri ReleasesPage = new($"https://github.com/{Repository}/releases");

    private const string InstallerPrefix = "ThermoForge-Setup-";
    private const string ChecksumsName = "SHA256SUMS.txt";
    private static readonly Uri LatestRelease = new($"https://api.github.com/repos/{Repository}/releases/latest");

    private readonly HttpClient _http;
    private readonly Lazy<SignatureInfo> _currentSignature;

    /// <param name="currentSignature">This copy's signature; read from the running exe when omitted.</param>
    public UpdateChecker(HttpClient http, Version current, SignatureInfo? currentSignature = null)
    {
        _http = http;
        Current = current;
        _currentSignature = new(() => currentSignature ?? AuthenticodeVerifier.Verify(Environment.ProcessPath!));
    }

    public Version Current { get; }

    /// <summary>This build's version, e.g. 1.0.0 (from the assembly's informational version).</summary>
    public static Version CurrentVersion()
    {
        var informational = Assembly.GetEntryAssembly()?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        return ParseVersion(informational?.Split('+')[0]) ?? new Version(0, 0, 0);
    }

    /// <summary>The newer release, or null when this copy is up to date (or nothing is published yet).</summary>
    /// <exception cref="UpdateException">GitHub couldn't be reached or answered unexpectedly.</exception>
    public async Task<AvailableUpdate?> CheckAsync(CancellationToken ct = default)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(20));
            using var request = new HttpRequestMessage(HttpMethod.Get, LatestRelease);
            request.Headers.Accept.ParseAdd("application/vnd.github+json");
            using var response = await _http.SendAsync(request, timeout.Token);
            if (response.StatusCode == HttpStatusCode.NotFound)
                return null; // No release published yet.
            if (response.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests)
                throw new UpdateException("GitHub is limiting requests from this network right now. Try again in an hour.");
            if (!response.IsSuccessStatusCode)
                throw new UpdateException($"GitHub answered {(int)response.StatusCode} {response.StatusCode}.");

            return Parse(await response.Content.ReadAsStringAsync(timeout.Token), Current);
        }
        catch (HttpRequestException ex)
        {
            throw new UpdateException($"Could not reach GitHub: {ex.Message}", ex);
        }
        catch (TaskCanceledException ex) when (!ct.IsCancellationRequested)
        {
            throw new UpdateException("GitHub didn't answer in time. Check your internet connection.", ex);
        }
    }

    /// <summary>Downloads and verifies the installer; returns its path.</summary>
    /// <param name="folder">Where to save it (created if needed).</param>
    /// <param name="progress">Reports 0–1 as the download proceeds.</param>
    /// <exception cref="UpdateException">Download failed, or the file isn't the one GitHub's checksums or the signature describe.</exception>
    public async Task<string> DownloadAsync(AvailableUpdate update, string folder, IProgress<double>? progress = null, CancellationToken ct = default)
    {
        if (update.Checksums is null)
            throw new UpdateException($"Release {update.Version} has no {ChecksumsName}, so its installer can't be verified. Download it from the releases page instead.");

        Directory.CreateDirectory(folder);
        var path = Path.Combine(folder, update.Installer.Name);
        try
        {
            var sums = await _http.GetStringAsync(update.Checksums.DownloadUrl, ct);
            var expected = ExpectedHash(sums, update.Installer.Name)
                ?? throw new UpdateException($"{ChecksumsName} doesn't list {update.Installer.Name}.");

            using (var response = await _http.GetAsync(update.Installer.DownloadUrl, HttpCompletionOption.ResponseHeadersRead, ct))
            {
                response.EnsureSuccessStatusCode();
                var total = response.Content.Headers.ContentLength ?? update.Installer.Size;
                await using var source = await response.Content.ReadAsStreamAsync(ct);
                await using var target = File.Create(path);
                var buffer = new byte[81920];
                long done = 0;
                int read;
                while ((read = await source.ReadAsync(buffer, ct)) > 0)
                {
                    await target.WriteAsync(buffer.AsMemory(0, read), ct);
                    done += read;
                    if (total > 0)
                        progress?.Report(Math.Min(1, done / (double)total));
                }
            }

            await using (var file = File.OpenRead(path))
            {
                var actual = Convert.ToHexString(await SHA256.HashDataAsync(file, ct));
                if (!actual.Equals(expected, StringComparison.OrdinalIgnoreCase))
                    throw new UpdateException("The downloaded installer doesn't match the release's checksum. It may be corrupted or tampered with, so it won't be run.");
            }

            CheckPublisher(AuthenticodeVerifier.Verify(path), _currentSignature.Value);
            return path;
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or UnauthorizedAccessException or UpdateException)
        {
            TryDelete(path);
            throw ex as UpdateException ?? new UpdateException($"Download failed: {ex.Message}", ex);
        }
        catch (OperationCanceledException)
        {
            TryDelete(path);
            throw;
        }
    }

    /// <summary>
    /// Once ThermoForge is code-signed, an update must be signed by the same publisher; until then
    /// the checksum is the only guarantee. An update can never drop or change the signature.
    /// </summary>
    internal static void CheckPublisher(SignatureInfo installer, SignatureInfo current)
    {
        if (current.Status != SignatureStatus.Signed)
            return;
        if (installer.Status != SignatureStatus.Signed || !string.Equals(installer.Signer, current.Signer, StringComparison.Ordinal))
            throw new UpdateException(
                $"The update isn't signed by {current.Signer} like this copy of ThermoForge, so it won't be run.");
    }

    internal static AvailableUpdate? Parse(string json, Version current)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            var release = document.RootElement;
            if (release.TryGetProperty("draft", out var draft) && draft.GetBoolean()
                || release.TryGetProperty("prerelease", out var pre) && pre.GetBoolean())
                return null;

            var version = ParseVersion(release.GetProperty("tag_name").GetString());
            if (version is null || version <= current)
                return null;

            var assets = release.GetProperty("assets").EnumerateArray()
                .Select(a => new ReleaseAsset(
                    a.GetProperty("name").GetString() ?? "",
                    new Uri(a.GetProperty("browser_download_url").GetString()!),
                    a.TryGetProperty("size", out var size) ? size.GetInt64() : 0))
                .ToList();
            var installer = assets.FirstOrDefault(a =>
                a.Name.StartsWith(InstallerPrefix, StringComparison.OrdinalIgnoreCase) && a.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase));
            if (installer is null)
                return null; // Nothing this app can install.

            return new AvailableUpdate(
                version,
                release.TryGetProperty("name", out var name) && name.GetString() is { Length: > 0 } title ? title : $"ThermoForge {version}",
                release.TryGetProperty("body", out var body) ? body.GetString() ?? "" : "",
                new Uri(release.GetProperty("html_url").GetString()!),
                release.TryGetProperty("published_at", out var published) && published.ValueKind == JsonValueKind.String
                    ? published.GetDateTime().ToLocalTime()
                    : null,
                installer,
                assets.FirstOrDefault(a => a.Name.Equals(ChecksumsName, StringComparison.OrdinalIgnoreCase)));
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or UriFormatException or FormatException)
        {
            throw new UpdateException("GitHub sent release details ThermoForge doesn't understand.", ex);
        }
    }

    /// <summary>"v1.2.3" or "1.2.3" to a version; null for anything else (e.g. "nightly").</summary>
    internal static Version? ParseVersion(string? tag)
    {
        var text = tag?.Trim().TrimStart('v', 'V');
        if (!Version.TryParse(text, out var version))
            return null;
        // Treat 1.2 and 1.2.0 alike, so a re-tagged release doesn't look new.
        return new Version(version.Major, version.Minor, Math.Max(version.Build, 0));
    }

    /// <summary>Reads a sha256sum-style line ("&lt;hash&gt;  &lt;file&gt;") for one file.</summary>
    internal static string? ExpectedHash(string sums, string fileName) =>
        sums.Split('\n')
            .Select(line => line.Trim().Split(' ', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Where(parts => parts.Length == 2 && parts[0].Length == 64 && parts[1].TrimStart('*') == fileName)
            .Select(parts => parts[0])
            .FirstOrDefault();

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }
}
