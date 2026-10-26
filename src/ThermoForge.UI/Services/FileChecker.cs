using System.IO;
using System.Net.Http;
using System.Windows;
using ThermoForge.Core.Reputation;

namespace ThermoForge.UI.Services;

/// <summary>
/// The "Check on VirusTotal" and "Scan with Defender" actions shared by the Processes, Startup
/// and Security tabs. Results go into the <see cref="ReputationStore"/>, where the monitors
/// pick them up as findings.
/// </summary>
public sealed class FileChecker
{
    private static readonly HttpClient Http = CreateHttpClient();

    private readonly AppSettings _settings;
    private VirusTotalClient? _virusTotal;

    public FileChecker(ReputationStore store, AppSettings settings)
    {
        Store = store;
        _settings = settings;
        if (ApiKey.Unprotect(settings.VirusTotalKeyProtected) is { } key)
            _virusTotal = new VirusTotalClient(Http, key);
    }

    public ReputationStore Store { get; }

    public bool HasVirusTotalKey => _virusTotal is not null;

    /// <summary>A VirusTotal check was asked for without a key; the Security tab should open.</summary>
    public event EventHandler? KeyNeeded;

    /// <summary>Saves (or with null, removes) the VirusTotal key, encrypted for this Windows user.</summary>
    public void SetVirusTotalKey(string? key)
    {
        key = string.IsNullOrWhiteSpace(key) ? null : key.Trim();
        _settings.VirusTotalKeyProtected = key is null ? null : ApiKey.Protect(key);
        _settings.Save();
        _virusTotal = key is null ? null : new VirusTotalClient(Http, key);
    }

    public void RequestKey() => KeyNeeded?.Invoke(this, EventArgs.Empty);

    /// <summary>Sends the file's SHA-256 (not the file) to VirusTotal.</summary>
    /// <exception cref="VirusTotalException">No key, rejected key, quota, or network trouble.</exception>
    /// <exception cref="IOException">The file can't be read.</exception>
    public async Task<FileReputation> CheckVirusTotalAsync(string path, CancellationToken ct = default)
    {
        var client = _virusTotal ?? throw new VirusTotalException("Add your free VirusTotal API key on the Security tab first.");
        var sha = await HashAsync(path);
        var report = await client.LookUpAsync(sha, ct);
        return Store.RecordVirusTotal(path, sha, report);
    }

    /// <exception cref="InvalidOperationException">Defender is missing or couldn't scan the file.</exception>
    /// <exception cref="IOException">The file can't be read.</exception>
    public async Task<FileReputation> ScanWithDefenderAsync(string path, CancellationToken ct = default)
    {
        var sha = await HashAsync(path);
        var result = await Defender.ScanFileAsync(path, ct);
        return Store.RecordDefender(path, sha, result);
    }

    /// <summary>"Check on VirusTotal" button: runs the check and reports the outcome in a message box.</summary>
    /// <returns>The updated results, or null when the check didn't happen.</returns>
    public async Task<FileReputation?> CheckVirusTotalInteractiveAsync(string path)
    {
        if (!HasVirusTotalKey)
        {
            var answer = MessageBox.Show(
                "To check files on VirusTotal, add your free API key on the Security tab. Only the file's fingerprint (SHA-256) is sent, never the file itself.\n\nOpen the Security tab now?",
                "VirusTotal key needed", MessageBoxButton.YesNo, MessageBoxImage.Information);
            if (answer == MessageBoxResult.Yes)
                RequestKey();
            return null;
        }

        try
        {
            var result = await CheckVirusTotalAsync(path);
            var bad = result.VirusTotal!.Malicious > 0;
            MessageBox.Show($"{Path.GetFileName(path)}\n\n{result.Summary.Split(Environment.NewLine)[0]}",
                "VirusTotal", MessageBoxButton.OK, bad ? MessageBoxImage.Warning : MessageBoxImage.Information);
            return result;
        }
        catch (Exception ex) when (ex is VirusTotalException or IOException)
        {
            MessageBox.Show(ex.Message, "VirusTotal check failed", MessageBoxButton.OK, MessageBoxImage.Warning);
            return null;
        }
    }

    /// <summary>"Scan with Defender" button: scans without quarantining and reports the outcome.</summary>
    public async Task<FileReputation?> ScanWithDefenderInteractiveAsync(string path)
    {
        try
        {
            var result = await ScanWithDefenderAsync(path);
            MessageBox.Show(
                result.Defender!.Threat is { } threat
                    ? $"{Path.GetFileName(path)}\n\nMicrosoft Defender detects this file as {threat}.\n\n"
                      + "Nothing was deleted. End the program and remove the file, or let Windows Security handle it."
                    : $"{Path.GetFileName(path)}\n\nMicrosoft Defender found no threat in this file.",
                "Microsoft Defender scan", MessageBoxButton.OK,
                result.Defender.Threat is null ? MessageBoxImage.Information : MessageBoxImage.Warning);
            return result;
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException)
        {
            MessageBox.Show(ex.Message, "Defender scan failed", MessageBoxButton.OK, MessageBoxImage.Warning);
            return null;
        }
    }

    private Task<string> HashAsync(string path) => Task.Run(() =>
        Store.Hashes.Sha256(path) ?? throw new IOException($"Could not read {path}. It may have been deleted, or Windows denies access."));

    private static HttpClient CreateHttpClient()
    {
        var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("ThermoForge/1.0");
        return http;
    }
}
