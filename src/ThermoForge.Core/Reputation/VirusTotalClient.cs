using System.Net;
using System.Text.Json;

namespace ThermoForge.Core.Reputation;

/// <summary>A VirusTotal lookup failed for a reason the user can act on.</summary>
public sealed class VirusTotalException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// Looks files up on VirusTotal by SHA-256 (API v3). Only the hash is sent, never the file, so
/// files VirusTotal has never seen come back as <see cref="VirusTotalVerdict.NotFound"/>.
/// Requests are spaced out to stay within the free tier's 4 lookups per minute. Thread-safe.
/// </summary>
public sealed class VirusTotalClient
{
    public static readonly TimeSpan FreeTierSpacing = TimeSpan.FromSeconds(15);

    private const string FilesEndpoint = "https://www.virustotal.com/api/v3/files/";

    private readonly HttpClient _http;
    private readonly string _apiKey;
    private readonly TimeSpan _spacing;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private DateTime _lastRequestUtc = DateTime.MinValue;

    /// <param name="spacing">Minimum time between two requests; defaults to <see cref="FreeTierSpacing"/>.</param>
    public VirusTotalClient(HttpClient http, string apiKey, TimeSpan? spacing = null)
    {
        _http = http;
        _apiKey = apiKey;
        _spacing = spacing ?? FreeTierSpacing;
    }

    /// <exception cref="VirusTotalException">Bad key, quota used up, or no connection.</exception>
    public async Task<VirusTotalReport> LookUpAsync(string sha256, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            var wait = _lastRequestUtc + _spacing - DateTime.UtcNow;
            if (wait > TimeSpan.Zero)
                await Task.Delay(wait, ct);
            _lastRequestUtc = DateTime.UtcNow;

            using var request = new HttpRequestMessage(HttpMethod.Get, FilesEndpoint + sha256);
            request.Headers.Add("x-apikey", _apiKey);

            using var response = await _http.SendAsync(request, ct);
            var body = await response.Content.ReadAsStringAsync(ct);
            return response.StatusCode switch
            {
                HttpStatusCode.OK => Parse(body, DateTime.Now),
                HttpStatusCode.NotFound => VirusTotalReport.NotFound(DateTime.Now),
                HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => throw new VirusTotalException(
                    "VirusTotal rejected the API key. Check it on the Security tab (copy it again from your VirusTotal profile)."),
                HttpStatusCode.TooManyRequests => throw new VirusTotalException(
                    "VirusTotal's limit for this key is used up (free keys allow 4 lookups a minute and 500 a day). Try again later."),
                var status => throw new VirusTotalException($"VirusTotal answered {(int)status} {status}. Try again later."),
            };
        }
        catch (HttpRequestException ex)
        {
            throw new VirusTotalException($"Could not reach VirusTotal: {ex.Message}", ex);
        }
        catch (TaskCanceledException ex) when (!ct.IsCancellationRequested)
        {
            throw new VirusTotalException("VirusTotal didn't answer in time. Check your internet connection.", ex);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Reads a v3 file object ({"data": {"attributes": {...}}}).</summary>
    internal static VirusTotalReport Parse(string json, DateTime checkedAt)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            var attributes = document.RootElement.GetProperty("data").GetProperty("attributes");
            var stats = attributes.GetProperty("last_analysis_stats");
            int Stat(string name) => stats.TryGetProperty(name, out var value) ? value.GetInt32() : 0;

            var malicious = Stat("malicious");
            var suspicious = Stat("suspicious");
            // Engines that couldn't handle the file type or timed out gave no verdict.
            var engines = malicious + suspicious + Stat("undetected") + Stat("harmless");

            string? label = null;
            if (attributes.TryGetProperty("popular_threat_classification", out var classification)
                && classification.TryGetProperty("suggested_threat_label", out var suggested))
                label = suggested.GetString();

            DateTime? analysed = attributes.TryGetProperty("last_analysis_date", out var date) && date.ValueKind == JsonValueKind.Number
                ? DateTimeOffset.FromUnixTimeSeconds(date.GetInt64()).LocalDateTime
                : null;

            var verdict = malicious > 0 ? VirusTotalVerdict.Malicious
                : suspicious > 0 ? VirusTotalVerdict.Suspicious
                : VirusTotalVerdict.Clean;
            return new VirusTotalReport(verdict, malicious, suspicious, engines, label, analysed, checkedAt);
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
        {
            throw new VirusTotalException("VirusTotal sent an answer ThermoForge doesn't understand.", ex);
        }
    }
}
