using System.Net;
using System.Security.Cryptography;
using ThermoForge.Core.Processes;
using ThermoForge.Core.Updates;

namespace ThermoForge.Tests;

public sealed class UpdateCheckerTests : IDisposable
{
    private static readonly Version Current = new(1, 0, 0);
    private static readonly byte[] Installer = "pretend installer"u8.ToArray();
    private static readonly string InstallerHash = Convert.ToHexString(SHA256.HashData(Installer)).ToLowerInvariant();

    private readonly string _dir = Directory.CreateTempSubdirectory("tf-update-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static string Release(string tag = "v1.1.0", bool prerelease = false, bool withSums = true, string installer = "ThermoForge-Setup-1.1.0.exe") => $$"""
        {
          "tag_name": "{{tag}}", "name": "ThermoForge {{tag}}", "draft": false, "prerelease": {{(prerelease ? "true" : "false")}},
          "body": "## What's new\n- Faster scans", "html_url": "https://github.com/gaaloulv36/thermoforge/releases/tag/{{tag}}",
          "published_at": "2026-11-02T10:00:00Z",
          "assets": [
            { "name": "ThermoForge-1.1.0-portable-win-x64.zip", "browser_download_url": "https://example.test/portable.zip", "size": 10 },
            { "name": "{{installer}}", "browser_download_url": "https://example.test/setup.exe", "size": 17 }
            {{(withSums ? """, { "name": "SHA256SUMS.txt", "browser_download_url": "https://example.test/sums", "size": 100 }""" : "")}}
          ]
        }
        """;

    /// <summary>Serves a release, its checksums and the installer like GitHub would.</summary>
    private sealed class FakeGitHub(Func<Uri, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public List<Uri> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Add(request.RequestUri!);
            return Task.FromResult(respond(request.RequestUri!));
        }
    }

    private static HttpResponseMessage Ok(string text) => new(HttpStatusCode.OK) { Content = new StringContent(text) };

    private static UpdateChecker Checker(Func<Uri, HttpResponseMessage> respond, SignatureInfo? current = null) =>
        new(new HttpClient(new FakeGitHub(respond)), Current, current ?? new SignatureInfo(SignatureStatus.Unsigned, null, null));

    private static HttpResponseMessage Serve(Uri uri, byte[] installer, string sums) => uri.AbsolutePath switch
    {
        "/sums" => Ok(sums),
        "/setup.exe" => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(installer) },
        _ => Ok(Release()),
    };

    [Fact]
    public void Parse_FindsTheInstallerChecksumsAndNotes()
    {
        var update = UpdateChecker.Parse(Release(), Current)!;

        Assert.Equal(new Version(1, 1, 0), update.Version);
        Assert.Equal("ThermoForge-Setup-1.1.0.exe", update.Installer.Name);
        Assert.Equal("SHA256SUMS.txt", update.Checksums!.Name);
        Assert.Contains("Faster scans", update.Notes);
        Assert.Equal("https://github.com/gaaloulv36/thermoforge/releases/tag/v1.1.0", update.Page.ToString());
    }

    [Theory]
    [InlineData("v1.0.0")]
    [InlineData("v0.9.5")]
    [InlineData("1.0")]
    [InlineData("nightly")]
    public void Parse_IgnoresReleasesThatAreNotNewer(string tag) =>
        Assert.Null(UpdateChecker.Parse(Release(tag), Current));

    [Fact]
    public void Parse_IgnoresPrereleases_AndReleasesWithoutAnInstaller()
    {
        Assert.Null(UpdateChecker.Parse(Release(prerelease: true), Current));
        Assert.Null(UpdateChecker.Parse(Release(installer: "something-else.exe"), Current));
    }

    [Theory]
    [InlineData("v1.2.3", "1.2.3")]
    [InlineData("1.2", "1.2.0")]
    [InlineData(" V2.0.1 ", "2.0.1")]
    public void ParseVersion_AcceptsCommonTagStyles(string tag, string expected) =>
        Assert.Equal(Version.Parse(expected), UpdateChecker.ParseVersion(tag));

    [Fact]
    public void ExpectedHash_ReadsSha256SumLines()
    {
        var sums = $"{InstallerHash}  ThermoForge-Setup-1.1.0.exe\r\n{new string('a', 64)}  ThermoForge-1.1.0-portable-win-x64.zip\r\n";

        Assert.Equal(InstallerHash, UpdateChecker.ExpectedHash(sums, "ThermoForge-Setup-1.1.0.exe"));
        Assert.Null(UpdateChecker.ExpectedHash(sums, "other.exe"));
    }

    [Fact]
    public async Task Check_ReturnsNullWhenNothingIsPublished()
    {
        var checker = Checker(_ => new HttpResponseMessage(HttpStatusCode.NotFound));
        Assert.Null(await checker.CheckAsync());
    }

    [Fact]
    public async Task Check_RateLimit_IsExplained()
    {
        var checker = Checker(_ => new HttpResponseMessage(HttpStatusCode.Forbidden));
        var ex = await Assert.ThrowsAsync<UpdateException>(() => checker.CheckAsync());
        Assert.Contains("limiting", ex.Message);
    }

    [Fact]
    public async Task Download_KeepsAFileThatMatchesItsChecksum()
    {
        var checker = Checker(uri => Serve(uri, Installer, $"{InstallerHash}  ThermoForge-Setup-1.1.0.exe"));
        var update = (await checker.CheckAsync())!;
        var progress = new List<double>();

        var path = await checker.DownloadAsync(update, _dir, new SyncProgress(progress.Add));

        Assert.Equal(Installer, await File.ReadAllBytesAsync(path));
        Assert.Equal(1.0, progress[^1]);
    }

    [Fact]
    public async Task Download_RejectsAndDeletesATamperedFile()
    {
        var checker = Checker(uri => Serve(uri, "evil installer"u8.ToArray(), $"{InstallerHash}  ThermoForge-Setup-1.1.0.exe"));
        var update = (await checker.CheckAsync())!;

        var ex = await Assert.ThrowsAsync<UpdateException>(() => checker.DownloadAsync(update, _dir));

        Assert.Contains("checksum", ex.Message);
        Assert.Empty(Directory.GetFiles(_dir));
    }

    [Fact]
    public async Task Download_RefusesAReleaseWithoutChecksums()
    {
        var update = UpdateChecker.Parse(Release(withSums: false), Current)!;
        await Assert.ThrowsAsync<UpdateException>(() => Checker(_ => Ok("")).DownloadAsync(update, _dir));
    }

    [Fact]
    public void Publisher_MustMatchOnceThisCopyIsSigned()
    {
        var signed = new SignatureInfo(SignatureStatus.Signed, "Forge Studio", null);
        var unsigned = new SignatureInfo(SignatureStatus.Unsigned, null, null);

        UpdateChecker.CheckPublisher(unsigned, unsigned); // Unsigned builds rely on the checksum.
        UpdateChecker.CheckPublisher(signed, signed);
        Assert.Throws<UpdateException>(() => UpdateChecker.CheckPublisher(unsigned, signed));
        Assert.Throws<UpdateException>(() => UpdateChecker.CheckPublisher(signed with { Signer = "Someone Else" }, signed));
    }

    [Theory]
    [InlineData(@"C:\Program Files\Forge Studio\ThermoForge\ThermoForge.exe", @"C:\Program Files\Forge Studio\ThermoForge\", true)]
    [InlineData(@"C:\Program Files\Forge Studio\ThermoForge\ThermoForge.exe", @"c:\program files\forge studio\thermoforge", true)]
    [InlineData(@"C:\Users\me\Downloads\ThermoForge\ThermoForge.exe", @"C:\Program Files\Forge Studio\ThermoForge\", false)]
    [InlineData(@"C:\Program Files\Forge Studio\ThermoForge\ThermoForge.exe", null, false)]
    public void InstalledCopy_IsTheOneInTheInstallFolder(string exe, string? folder, bool expected) =>
        Assert.Equal(expected, Installation.IsInside(exe, folder));

    /// <summary>Progress&lt;T&gt; posts to the thread pool; this one reports immediately.</summary>
    private sealed class SyncProgress(Action<double> report) : IProgress<double>
    {
        public void Report(double value) => report(value);
    }
}
