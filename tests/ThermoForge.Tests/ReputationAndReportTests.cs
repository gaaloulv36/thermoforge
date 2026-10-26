using System.Net;
using System.Text;
using ThermoForge.Core.Alerts;
using ThermoForge.Core.Processes;
using ThermoForge.Core.Reports;
using ThermoForge.Core.Reputation;
using ThermoForge.Core.Services;
using ThermoForge.Core.Startup;

namespace ThermoForge.Tests;

public class VirusTotalClientTests
{
    private const string Sha = "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F";

    private const string MaliciousJson = """
        {"data":{"id":"x","attributes":{
          "last_analysis_date":1767225600,
          "last_analysis_stats":{"malicious":12,"suspicious":1,"undetected":55,"harmless":0,"timeout":2,"type-unsupported":4},
          "popular_threat_classification":{"suggested_threat_label":"trojan.coinminer/xmrig"}}}}
        """;

    private sealed class FakeHandler(HttpStatusCode status, string body) : HttpMessageHandler
    {
        public HttpRequestMessage? Request { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Request = request;
            return Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") });
        }
    }

    private static (VirusTotalClient Client, FakeHandler Handler) Client(HttpStatusCode status, string body = "{}")
    {
        var handler = new FakeHandler(status, body);
        return (new VirusTotalClient(new HttpClient(handler), "secret-key", TimeSpan.Zero), handler);
    }

    [Fact]
    public void Parse_ReadsStatsLabelAndDate()
    {
        var report = VirusTotalClient.Parse(MaliciousJson, DateTime.Now);

        Assert.Equal(VirusTotalVerdict.Malicious, report.Verdict);
        Assert.Equal(12, report.Malicious);
        Assert.Equal(1, report.Suspicious);
        Assert.Equal(68, report.Engines); // Timeouts and unsupported types gave no verdict.
        Assert.Equal("trojan.coinminer/xmrig", report.ThreatLabel);
        Assert.Equal(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc).ToLocalTime(), report.LastAnalysis);
    }

    [Fact]
    public void Parse_CleanFile()
    {
        var report = VirusTotalClient.Parse(
            """{"data":{"attributes":{"last_analysis_stats":{"malicious":0,"suspicious":0,"undetected":60,"harmless":10}}}}""", DateTime.Now);

        Assert.Equal(VirusTotalVerdict.Clean, report.Verdict);
        Assert.Equal(70, report.Engines);
        Assert.Null(report.ThreatLabel);
    }

    [Fact]
    public async Task LookUp_SendsOnlyTheHashWithTheKeyHeader()
    {
        var (client, handler) = Client(HttpStatusCode.OK, MaliciousJson);

        await client.LookUpAsync(Sha);

        Assert.Equal($"https://www.virustotal.com/api/v3/files/{Sha}", handler.Request!.RequestUri!.ToString());
        Assert.Equal(HttpMethod.Get, handler.Request.Method);
        Assert.Equal("secret-key", Assert.Single(handler.Request.Headers.GetValues("x-apikey")));
    }

    [Fact]
    public async Task LookUp_UnknownFile_IsNotFound()
    {
        var (client, _) = Client(HttpStatusCode.NotFound);
        Assert.Equal(VirusTotalVerdict.NotFound, (await client.LookUpAsync(Sha)).Verdict);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized, "rejected the API key")]
    [InlineData(HttpStatusCode.TooManyRequests, "limit")]
    [InlineData(HttpStatusCode.InternalServerError, "500")]
    public async Task LookUp_ErrorsExplainWhatToDo(HttpStatusCode status, string message)
    {
        var (client, _) = Client(status);
        var ex = await Assert.ThrowsAsync<VirusTotalException>(() => client.LookUpAsync(Sha));
        Assert.Contains(message, ex.Message);
    }
}

public class FileReputationTests
{
    private static VirusTotalReport Vt(int malicious, int suspicious = 0) =>
        new(malicious > 0 ? VirusTotalVerdict.Malicious : suspicious > 0 ? VirusTotalVerdict.Suspicious : VirusTotalVerdict.Clean,
            malicious, suspicious, 70, null, null, DateTime.Now);

    [Theory]
    [InlineData(0, 0, null)]
    [InlineData(0, 2, FindingSeverity.Low)]
    [InlineData(1, 0, FindingSeverity.Low)]
    [InlineData(3, 0, FindingSeverity.Medium)]
    [InlineData(12, 0, FindingSeverity.High)]
    public void VirusTotalDetections_BecomeFindingsByHowManyEnginesAgree(int malicious, int suspicious, FindingSeverity? expected)
    {
        var findings = new FileReputation("A", @"C:\x.exe", Vt(malicious, suspicious), null).Findings();

        Assert.Equal(expected, findings.SingleOrDefault()?.Severity);
    }

    [Fact]
    public void DefenderDetection_IsHigh_AndCleanScanAddsNothing()
    {
        Assert.Equal(FindingSeverity.High,
            Assert.Single(new FileReputation("A", "x", null, new(DateTime.Now, "Trojan:Win32/Test")).Findings()).Severity);
        Assert.Empty(new FileReputation("A", "x", null, new(DateTime.Now, null)).Findings());
    }

    [Fact]
    public void Summary_HasOneLinePerScanner()
    {
        var summary = new FileReputation("A", "x", Vt(0), new(DateTime.Now, null)).Summary;

        Assert.Equal(2, summary.Split(Environment.NewLine).Length);
        Assert.Contains("0 of 70", summary);
        Assert.Contains("no threat found", summary);
    }
}

public sealed class ReputationStoreTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("tf-rep-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string NewFile(string content)
    {
        var path = Path.Combine(_dir, $"{Guid.NewGuid():N}.exe");
        File.WriteAllText(path, content);
        return path;
    }

    [Fact]
    public void ResultsApplyToTheExactFile_AndSurviveRestarts()
    {
        var file = NewFile("program");
        var storePath = Path.Combine(_dir, "reputation.json");
        var hashes = new FileHashCache();
        var store = new ReputationStore(storePath, hashes);

        Assert.Null(store.For(file));
        store.RecordDefender(file, hashes.Sha256(file)!, new DefenderScanResult(DateTime.Now, "Trojan:Win32/Test"));

        Assert.Equal("Trojan:Win32/Test", store.For(file)!.Defender!.Threat);
        Assert.Equal("Trojan:Win32/Test", new ReputationStore(storePath, new FileHashCache()).For(file)!.Defender!.Threat);
    }

    [Fact]
    public void ChangedFile_LosesItsResults()
    {
        var file = NewFile("version 1");
        var hashes = new FileHashCache();
        var store = new ReputationStore(null, hashes);
        store.RecordVirusTotal(file, hashes.Sha256(file)!, VirusTotalReport.NotFound(DateTime.Now));

        File.WriteAllText(file, "version 2 is longer");

        Assert.Null(store.For(file));
    }

    [Fact]
    public void BothScannersAreKept()
    {
        var file = NewFile("both");
        var hashes = new FileHashCache();
        var store = new ReputationStore(null, hashes);
        var sha = hashes.Sha256(file)!;

        store.RecordVirusTotal(file, sha, VirusTotalReport.NotFound(DateTime.Now));
        var both = store.RecordDefender(file, sha, new DefenderScanResult(DateTime.Now, null));

        Assert.NotNull(both.VirusTotal);
        Assert.NotNull(both.Defender);
        Assert.Single(store.All);
    }

    [Fact]
    public void StartupScanner_AddsDetectionsToTheEntry()
    {
        var file = NewFile("startup program");
        var hashes = new FileHashCache();
        var store = new ReputationStore(null, hashes);
        store.RecordDefender(file, hashes.Sha256(file)!, new DefenderScanResult(DateTime.Now, "Trojan:Win32/Test"));
        var scanner = new StartupScanner(
            [new OneEntry(new RawStartupEntry(StartupSource.RunKey, "Bad", @"HKCU\...\Run", $"\"{file}\""))],
            new StartupCommand(@"C:\Windows", File.Exists),
            new ProcessAnalyzer(@"C:\Windows"),
            new TrustStore(Path.Combine(_dir, "trust.json")),
            new StartupBaseline(null),
            File.Exists,
            _ => new FileMetadata(new SignatureInfo(SignatureStatus.Signed, "Contoso", null), null, null),
            isAdministrator: false,
            reputation: store);

        var entry = Assert.Single(scanner.Scan().Entries);

        Assert.Equal(FindingSeverity.High, entry.Severity);
        Assert.NotNull(entry.Reputation);
    }

    private sealed class OneEntry(RawStartupEntry entry) : IStartupSource
    {
        public IEnumerable<RawStartupEntry> Read(ICollection<string> errors) => [entry];
    }
}

public class DefenderTests
{
    [Fact]
    public void ParseScan_CleanAndThreat()
    {
        const string output = """
            Scan starting...
            Scan finished.
            Scanning C:\Temp\bad.exe found 1 threats.

            <===========================LIST OF DETECTED THREATS==========================>
            ----------------------------- Threat information ------------------------------
            Threat                  : Trojan:Win32/Wacatac.B!ml
            Resources               : 1 total
                file                : C:\Temp\bad.exe
            -------------------------------------------------------------------------------
            """;

        Assert.Null(Defender.ParseScan(0, "Scan finished.", DateTime.Now).Threat);
        Assert.Equal("Trojan:Win32/Wacatac.B!ml", Defender.ParseScan(2, output, DateTime.Now).Threat);
    }

    [Fact]
    public void ParseScan_OtherCodesAreErrors()
    {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            Defender.ParseScan(unchecked((int)0x80508023), "Scan starting...\nCmdTool: Failed with hr = 0x80508023. Check C:\\...\\MpCmdRun.log", DateTime.Now));
        Assert.Contains("0x80508023", ex.Message);
    }

    [Theory]
    [InlineData(@"file:_C:\Users\me\Downloads\x.exe", @"C:\Users\me\Downloads\x.exe")]
    [InlineData(@"containerfile:_C:\a.zip", @"C:\a.zip")]
    [InlineData(@"C:\plain.exe", @"C:\plain.exe")]
    public void CleanResource_StripsDefenderPrefixes(string resource, string expected) =>
        Assert.Equal(expected, Defender.CleanResource(resource));

    [Fact]
    public void Status_ReportsProblemsOnlyWhenDefenderIsInCharge()
    {
        var now = DateTime.Now;
        var healthy = new DefenderStatus("Normal", true, true, now.AddHours(-3), "4.18");

        Assert.Null(healthy.Problem(now));
        Assert.Contains("Real-time protection", (healthy with { RealTimeProtection = false }).Problem(now));
        Assert.Contains("days old", (healthy with { SignaturesUpdated = now.AddDays(-12) }).Problem(now));
        Assert.Null((healthy with { RunningMode = "Passive Mode", RealTimeProtection = false }).Problem(now));
    }

    [Fact]
    public void AlertEngine_AlertsOncePerProblem_AndOnlyForNewDetections()
    {
        var engine = new AlertEngine(TemperatureThresholds.Default);
        var now = DateTime.Now;
        var off = new DefenderStatus("Normal", true, false, now, null);
        var old = new DefenderDetection("1", now.AddDays(-3), "Old:Threat", "High", [@"C:\old.exe"], null, "Quarantined");
        var fresh = new DefenderDetection("2", now, "New:Threat", "Severe", [@"C:\new.exe"], null, "Detected");

        var first = engine.Evaluate(off, [old], now);
        Assert.Equal("Antivirus protection is off", Assert.Single(first).Title);
        Assert.Equal(AlertKind.Security, first[0].Kind);

        Assert.Empty(engine.Evaluate(off, [old], now));

        var second = engine.Evaluate(off with { RealTimeProtection = true }, [old, fresh], now);
        Assert.Equal("Microsoft Defender found New:Threat", Assert.Single(second).Title);
    }
}

public class ReportTests
{
    private static readonly RawProcess Evil = new(66, 1, "<script>alert(1)</script>.exe", @"C:\Users\me\AppData\Local\Temp\evil.exe", null, null);

    private static SecurityReport Build(params ProcessInfo[] processes) => ReportBuilder.Build(
        new ReportInputs(new ProcessSnapshot(DateTime.Now, processes), null, null, null, [], [], []),
        DateTime.Now,
        TemperatureThresholds.Default);

    [Fact]
    public void CleanPc_HasNoVerdict()
    {
        var report = Build(new ProcessInfo(Evil with { Name = "good.exe" }, null, 0, 0, 0, null, []));

        Assert.Equal(FindingSeverity.None, report.Verdict);
        Assert.Empty(report.Processes);
        Assert.Contains("No serious problems found", HtmlReport.Render(report));
    }

    [Fact]
    public void RiskyProcess_SetsTheVerdict_AndIsEncodedInHtml()
    {
        var info = new ProcessInfo(Evil, null, 0, 0, 0, null, [new(FindingSeverity.High, "Unsigned program running from a temporary folder", "d")]);

        var report = Build(info);
        var html = HtmlReport.Render(report);

        Assert.Equal(FindingSeverity.High, report.Verdict);
        Assert.Contains("Action needed", html);
        Assert.DoesNotContain("<script>", html);
        Assert.Contains("&lt;script&gt;", html);
    }

    [Fact]
    public void Json_UsesReadableEnumNames()
    {
        var json = Build(new ProcessInfo(Evil, null, 0, 0, 0, null, [new(FindingSeverity.Medium, "t", "d")])).ToJson();

        Assert.Contains("\"Verdict\": \"Medium\"", json);
    }
}
