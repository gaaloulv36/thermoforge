using ThermoForge.Core.Processes;

namespace ThermoForge.Tests;

public class RiskScoreTests
{
    private static ProcessFinding F(FindingSeverity severity) => new(severity, "t", "d");

    [Theory]
    [InlineData(new FindingSeverity[0], 0, FindingSeverity.None)]
    [InlineData(new[] { FindingSeverity.Low }, 10, FindingSeverity.Low)]
    [InlineData(new[] { FindingSeverity.Medium }, 30, FindingSeverity.Medium)]
    [InlineData(new[] { FindingSeverity.High }, 60, FindingSeverity.High)]
    [InlineData(new[] { FindingSeverity.Low, FindingSeverity.Low, FindingSeverity.Low }, 30, FindingSeverity.Medium)]
    [InlineData(new[] { FindingSeverity.Medium, FindingSeverity.Medium }, 60, FindingSeverity.High)]
    [InlineData(new[] { FindingSeverity.High, FindingSeverity.High }, 100, FindingSeverity.High)]
    public void WeakSignalsAddUp(FindingSeverity[] severities, int score, FindingSeverity level)
    {
        var findings = severities.Select(F).ToList();

        Assert.Equal(score, RiskScore.From(findings));
        Assert.Equal(level, RiskScore.Level(RiskScore.From(findings)));
    }

    [Fact]
    public void TrustedProcess_ScoresZeroButKeepsFindings()
    {
        var process = new RawProcess(1, 0, "x.exe", @"C:\x.exe", null, null);
        var info = new ProcessInfo(process, null, 0, 0, 0, null, [F(FindingSeverity.High)], IsTrusted: true);

        Assert.Equal(0, info.Risk);
        Assert.Equal(FindingSeverity.None, info.Severity);
        Assert.Single(info.Findings);
    }
}

public class BehaviorTrackerTests
{
    private static readonly DateTime T0 = new(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);
    private static readonly BehaviorTracker.ProcessKey Miner = new(42, T0);
    private static readonly TimeSpan Away = TimeSpan.FromMinutes(10);

    private static BehaviorTracker.Usage Use(double cpu, double gpu = 0, SignatureStatus? signature = SignatureStatus.Unsigned) =>
        new(Miner, cpu, gpu, signature);

    /// <summary>Feeds the same usage every 3 s for the given duration and returns the last result.</summary>
    private static IReadOnlyDictionary<BehaviorTracker.ProcessKey, ProcessFinding> Run(
        BehaviorTracker tracker, BehaviorTracker.Usage usage, TimeSpan duration, TimeSpan idle, DateTime? start = null)
    {
        IReadOnlyDictionary<BehaviorTracker.ProcessKey, ProcessFinding> last = new Dictionary<BehaviorTracker.ProcessKey, ProcessFinding>();
        var t = start ?? T0;
        for (var elapsed = TimeSpan.Zero; elapsed <= duration; elapsed += TimeSpan.FromSeconds(3))
            last = tracker.Observe([usage], t + elapsed, idle);
        return last;
    }

    [Fact]
    public void UnsignedHeavyCpuWhileAway_IsPossibleMiner()
    {
        var result = Run(new BehaviorTracker(), Use(cpu: 80), TimeSpan.FromMinutes(3), Away);

        var finding = Assert.Single(result).Value;
        Assert.Equal(FindingSeverity.High, finding.Severity);
        Assert.Equal("Possible crypto-miner", finding.Title);
        Assert.Contains("CPU", finding.Detail);
    }

    [Fact]
    public void HeavyGpuWhileAway_MentionsGraphicsCard()
    {
        var result = Run(new BehaviorTracker(), Use(cpu: 2, gpu: 95), TimeSpan.FromMinutes(3), Away);

        Assert.Contains("graphics card", Assert.Single(result).Value.Detail);
    }

    [Theory]
    [InlineData(SignatureStatus.Signed, FindingSeverity.Low)]
    [InlineData(SignatureStatus.Unknown, FindingSeverity.Medium)]
    [InlineData(null, FindingSeverity.Medium)]
    [InlineData(SignatureStatus.Invalid, FindingSeverity.High)]
    public void SeverityDependsOnSignature(SignatureStatus? signature, FindingSeverity expected)
    {
        var result = Run(new BehaviorTracker(), Use(cpu: 80, signature: signature), TimeSpan.FromMinutes(3), Away);

        Assert.Equal(expected, Assert.Single(result).Value.Severity);
    }

    [Fact]
    public void HeavyLoadWhileUserIsActive_IsNotReported() =>
        Assert.Empty(Run(new BehaviorTracker(), Use(cpu: 100), TimeSpan.FromMinutes(10), idle: TimeSpan.FromSeconds(5)));

    [Fact]
    public void ShortBurstWhileAway_IsNotReported() =>
        Assert.Empty(Run(new BehaviorTracker(), Use(cpu: 100), TimeSpan.FromMinutes(1), Away));

    [Fact]
    public void LightLoadWhileAway_IsNotReported() =>
        Assert.Empty(Run(new BehaviorTracker(), Use(cpu: 10, gpu: 20), TimeSpan.FromMinutes(10), Away));

    [Fact]
    public void BriefDip_DoesNotResetTheStreak()
    {
        var tracker = new BehaviorTracker();
        Run(tracker, Use(cpu: 80), TimeSpan.FromSeconds(90), Away);
        tracker.Observe([Use(cpu: 5)], T0 + TimeSpan.FromSeconds(93), Away);

        var result = Run(tracker, Use(cpu: 80), TimeSpan.FromSeconds(40), Away, start: T0 + TimeSpan.FromSeconds(96));

        Assert.Single(result);
    }

    [Fact]
    public void UserComingBack_ResetsTheStreak()
    {
        var tracker = new BehaviorTracker();
        Run(tracker, Use(cpu: 80), TimeSpan.FromSeconds(90), Away);
        tracker.Observe([Use(cpu: 80)], T0 + TimeSpan.FromSeconds(93), userIdle: TimeSpan.Zero);

        var result = Run(tracker, Use(cpu: 80), TimeSpan.FromSeconds(40), Away, start: T0 + TimeSpan.FromSeconds(96));

        Assert.Empty(result);
    }
}

public class ProcessPathTests
{
    [Theory]
    [InlineData(@"\\?\C:\Windows\system32\conhost.exe", @"C:\Windows\system32\conhost.exe")]
    [InlineData(@"\\?\UNC\server\share\tool.exe", @"\\server\share\tool.exe")]
    [InlineData(@"C:\Program Files\App\app.exe", @"C:\Program Files\App\app.exe")]
    [InlineData(@"\\server\share\tool.exe", @"\\server\share\tool.exe")]
    [InlineData(null, null)]
    public void CleanPath_StripsExtendedLengthPrefix(string? raw, string? expected) =>
        Assert.Equal(expected, ProcessMonitor.CleanPath(raw));

    [Fact]
    public void RealConhostWithExtendedPath_IsNotFlaggedAfterCleaning()
    {
        var path = ProcessMonitor.CleanPath(@"\\?\C:\Windows\system32\conhost.exe");
        var process = new RawProcess(1, 2, "conhost.exe", path, null, null);

        Assert.Empty(new ProcessAnalyzer(@"C:\Windows").Analyze(process, null, new SignatureInfo(SignatureStatus.Signed, "Microsoft Windows", null)));
    }
}

public class GpuUsageReaderTests
{
    [Fact]
    public void Aggregate_SumsEnginesOfOneTypeAndTakesBusiestType()
    {
        var result = GpuUsageReader.Aggregate(
        [
            ("pid_100_luid_0x0_0xD1A3_phys_0_eng_0_engtype_3D", 30),
            ("pid_100_luid_0x0_0xD1A3_phys_0_eng_1_engtype_3D", 25),
            ("pid_100_luid_0x0_0xD1A3_phys_0_eng_5_engtype_VideoDecode", 40),
            ("pid_200_luid_0x0_0xD1A3_phys_0_eng_0_engtype_Copy", 3),
            ("not a gpu instance", 99),
        ]);

        Assert.Equal(55, result[100]);
        Assert.Equal(3, result[200]);
        Assert.Equal(2, result.Count);
    }

    [Fact]
    public void Aggregate_ClampsTo100() =>
        Assert.Equal(100, GpuUsageReader.Aggregate(
        [
            ("pid_7_luid_a_phys_0_eng_0_engtype_3D", 80),
            ("pid_7_luid_b_phys_1_eng_0_engtype_3D", 80),
        ])[7]);
}

public sealed class TrustStoreTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "tf-trust-" + Guid.NewGuid().ToString("N"));
    private readonly string _exe;
    private readonly string _list;

    public TrustStoreTests()
    {
        Directory.CreateDirectory(_dir);
        _exe = Path.Combine(_dir, "tool.exe");
        _list = Path.Combine(_dir, "trusted.json");
        File.WriteAllText(_exe, "original contents");
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact]
    public void TrustedFile_IsTrustedAndSurvivesReload()
    {
        new TrustStore(_list).Trust(_exe, "tool.exe", "Contoso");

        var reloaded = new TrustStore(_list);
        Assert.True(reloaded.IsTrusted(_exe));
        Assert.True(reloaded.IsTrusted(_exe.ToUpperInvariant()));
        Assert.Equal("Contoso", Assert.Single(reloaded.Programs).Publisher);
    }

    [Fact]
    public void ReplacedFile_IsNoLongerTrusted()
    {
        var store = new TrustStore(_list);
        store.Trust(_exe, "tool.exe", null);

        File.WriteAllText(_exe, "malware swapped in");
        File.SetLastWriteTimeUtc(_exe, DateTime.UtcNow.AddMinutes(1));

        Assert.False(store.IsTrusted(_exe));
    }

    [Fact]
    public void Removed_IsNoLongerTrusted()
    {
        var store = new TrustStore(_list);
        store.Trust(_exe, "tool.exe", null);
        store.Remove(_exe);

        Assert.False(new TrustStore(_list).IsTrusted(_exe));
    }

    [Fact]
    public void CorruptList_StartsEmpty()
    {
        File.WriteAllText(_list, "{ not json");

        Assert.Empty(new TrustStore(_list).Programs);
    }
}
