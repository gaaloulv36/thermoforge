using ThermoForge.Core.Alerts;
using ThermoForge.Core.Processes;
using ThermoForge.Core.Startup;

namespace ThermoForge.Tests;

public class StartupCommandTests
{
    private static readonly HashSet<string> Files = new(StringComparer.OrdinalIgnoreCase)
    {
        @"C:\Program Files\Vendor App\app.exe",
        @"C:\Windows\System32\ctfmon.exe",
        @"C:\Windows\System32\rundll32.exe",
        @"C:\Windows\System32\drivers\acpi.sys",
        @"C:\Windows\explorer.exe",
        @"C:\Users\me\AppData\Roaming\evil\payload.dll",
    };

    private static readonly StartupCommand Parser = new(@"C:\Windows", Files.Contains,
        s => s.Replace("%APPDATA%", @"C:\Users\me\AppData\Roaming", StringComparison.OrdinalIgnoreCase));

    [Theory]
    [InlineData("\"C:\\Program Files\\Vendor App\\app.exe\" --minimized", @"C:\Program Files\Vendor App\app.exe")]
    [InlineData(@"C:\Program Files\Vendor App\app.exe --minimized", @"C:\Program Files\Vendor App\app.exe")]
    [InlineData("ctfmon.exe", @"C:\Windows\System32\ctfmon.exe")]
    [InlineData("explorer", @"C:\Windows\explorer.exe")]
    [InlineData(@"\SystemRoot\System32\drivers\acpi.sys", @"C:\Windows\System32\drivers\acpi.sys")]
    [InlineData(@"System32\drivers\acpi.sys", @"C:\Windows\System32\drivers\acpi.sys")]
    [InlineData(@"\??\C:\Windows\System32\drivers\acpi.sys", @"C:\Windows\System32\drivers\acpi.sys")]
    [InlineData(@"rundll32.exe %APPDATA%\evil\payload.dll,Start", @"C:\Users\me\AppData\Roaming\evil\payload.dll")]
    [InlineData("\"C:\\Gone\\old.exe\" /x", @"C:\Gone\old.exe")]
    public void ResolvesTheFileThatRuns(string command, string expected) =>
        Assert.Equal(expected, Parser.ResolveImage(command));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void EmptyCommand_HasNoImage(string? command) => Assert.Null(Parser.ResolveImage(command));
}

public class StartupApprovalTests
{
    [Theory]
    [InlineData(new byte[] { 0x02, 0, 0, 0 }, true)]
    [InlineData(new byte[] { 0x06, 0, 0, 0 }, true)]
    [InlineData(new byte[] { 0x03, 0, 0, 0 }, false)]
    [InlineData(new byte[] { 0x07, 0, 0, 0 }, false)]
    [InlineData(null, true)]
    public void ReadsTaskManagerState(byte[]? value, bool enabled) =>
        Assert.Equal(enabled, StartupApproval.IsEnabledValue(value));

    [Fact]
    public void WrittenValues_RoundTrip()
    {
        Assert.True(StartupApproval.IsEnabledValue(StartupApproval.MakeValue(true, DateTime.UtcNow)));
        var disabled = StartupApproval.MakeValue(false, DateTime.UtcNow);
        Assert.False(StartupApproval.IsEnabledValue(disabled));
        Assert.Equal(12, disabled.Length);
    }
}

public class WinlogonTests
{
    [Theory]
    [InlineData("explorer.exe", true)]
    [InlineData("Explorer.exe,", true)]
    [InlineData(@"explorer.exe, C:\Users\Public\evil.exe", false)]
    [InlineData(@"C:\Users\Public\evil.exe", false)]
    public void Shell(string value, bool isDefault) => Assert.Equal(isDefault, WinlogonSource.IsDefaultShell(value));

    [Theory]
    [InlineData(@"C:\Windows\system32\userinit.exe,", true)]
    [InlineData(@"C:\WINDOWS\System32\userinit.exe", true)]
    [InlineData(@"C:\Windows\system32\userinit.exe, C:\ProgramData\x.exe,", false)]
    public void Userinit(string value, bool isDefault) =>
        Assert.Equal(isDefault, WinlogonSource.IsDefaultUserinit(value, @"C:\Windows\system32"));
}

public class StartupBaselineTests
{
    private static readonly DateTime T0 = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    private static readonly HashSet<string> RunComplete = ["run|user"];

    private static IReadOnlyDictionary<string, StartupBaseline.Observation> See(
        StartupBaseline baseline, DateTime time, IReadOnlySet<string> complete, params string[] ids) =>
        baseline.Observe(ids.Select(id => (id, "run|user")), complete, time);

    [Fact]
    public void FirstScan_IsBaseline_LaterAdditionsAreNew()
    {
        var baseline = new StartupBaseline(null);
        Assert.False(See(baseline, T0, RunComplete, "a", "b")["a"].IsNew);

        var second = See(baseline, T0.AddHours(1), RunComplete, "a", "b", "c");
        Assert.False(second["a"].IsNew);
        Assert.True(second["c"].IsNew);

        // No longer "new" after a week.
        Assert.False(See(baseline, T0.AddDays(8), RunComplete, "a", "b", "c")["c"].IsNew);
    }

    [Fact]
    public void RemovedThenReadded_IsNewAgain_OnlyAfterACompleteScan()
    {
        var baseline = new StartupBaseline(null);
        See(baseline, T0, RunComplete, "a", "b");

        See(baseline, T0.AddHours(1), new HashSet<string>(), "a");
        Assert.False(See(baseline, T0.AddHours(2), RunComplete, "a", "b")["b"].IsNew);

        See(baseline, T0.AddHours(3), RunComplete, "a");
        Assert.True(See(baseline, T0.AddHours(4), RunComplete, "a", "b")["b"].IsNew);
    }

    [Fact]
    public void FirstEntryInAnEmptySource_IsNew()
    {
        var baseline = new StartupBaseline(null);
        HashSet<string> wmi = ["wmi|user"];
        baseline.Observe([], wmi, T0);

        var seen = baseline.Observe([("evil", "wmi|user")], wmi, T0.AddHours(1));

        Assert.True(seen["evil"].IsNew);
    }

    [Fact]
    public void EntriesRevealedByRunningAsAdmin_AreNotNew()
    {
        var baseline = new StartupBaseline(null);
        baseline.Observe([("visible", "tasks|user")], new HashSet<string> { "tasks|user" }, T0);

        var asAdmin = baseline.Observe([("visible", "tasks|admin"), ("hidden-before", "tasks|admin")],
            new HashSet<string> { "tasks|admin" }, T0.AddDays(1));

        Assert.False(asAdmin["visible"].IsNew);
        Assert.False(asAdmin["hidden-before"].IsNew);
    }

    [Fact]
    public void SurvivesReload()
    {
        var path = Path.Combine(Path.GetTempPath(), $"tf-baseline-{Guid.NewGuid():N}.json");
        try
        {
            See(new StartupBaseline(path), T0, RunComplete, "a");
            var seen = See(new StartupBaseline(path), T0.AddHours(1), RunComplete, "a", "b");

            Assert.False(seen["a"].IsNew);
            Assert.True(seen["b"].IsNew);
        }
        finally
        {
            File.Delete(path);
        }
    }
}

public class StartupScannerTests
{
    private sealed class FakeSource(params RawStartupEntry[] entries) : IStartupSource
    {
        public List<RawStartupEntry> Entries { get; } = [.. entries];
        public IEnumerable<RawStartupEntry> Read(ICollection<string> errors) => Entries;
    }

    private sealed class BrokenSource : IStartupSource
    {
        public IEnumerable<RawStartupEntry> Read(ICollection<string> errors) => throw new InvalidOperationException("boom");
    }

    private static readonly HashSet<string> Files = new(StringComparer.OrdinalIgnoreCase)
    {
        @"C:\Program Files\Good\good.exe",
        @"C:\Users\me\AppData\Local\Temp\svchost.exe",
        @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    };

    private static FileMetadata Meta(string path) => new(
        path.Contains("Good") || path.Contains("PowerShell")
            ? new SignatureInfo(SignatureStatus.Signed, "Contoso", null)
            : new SignatureInfo(SignatureStatus.Unsigned, null, null),
        null, null);

    private static StartupScanner Scanner(params IStartupSource[] sources) => new(
        sources,
        new StartupCommand(@"C:\Windows", Files.Contains),
        new ProcessAnalyzer(@"C:\Windows"),
        new TrustStore(Path.Combine(Path.GetTempPath(), $"tf-trust-{Guid.NewGuid():N}.json")),
        new StartupBaseline(null),
        Files.Contains,
        Meta,
        isAdministrator: false);

    private static RawStartupEntry Run(string name, string command) =>
        new(StartupSource.RunKey, name, @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", command);

    [Fact]
    public void SignedProgram_HasNoFindings()
    {
        var entry = Assert.Single(Scanner(new FakeSource(Run("Good", "\"C:\\Program Files\\Good\\good.exe\" /tray"))).Scan().Entries);

        Assert.Equal(@"C:\Program Files\Good\good.exe", entry.ImagePath);
        Assert.Empty(entry.Findings);
        Assert.Equal(FindingSeverity.None, entry.Severity);
    }

    [Fact]
    public void FakeSvchostInTemp_IsHighRisk()
    {
        var entry = Assert.Single(Scanner(new FakeSource(Run("Updater", @"C:\Users\me\AppData\Local\Temp\svchost.exe"))).Scan().Entries);

        Assert.Equal(FindingSeverity.High, entry.Severity);
        Assert.Contains(entry.Findings, f => f.Title.Contains("Impersonates"));
    }

    [Fact]
    public void MissingFile_IsReported()
    {
        var entry = Assert.Single(Scanner(new FakeSource(Run("Old", "\"C:\\Gone\\old.exe\""))).Scan().Entries);

        Assert.True(entry.FileMissing);
        Assert.Contains(entry.Findings, f => f.Title == "Points to a missing file");
    }

    [Fact]
    public void EncodedPowerShellAtSignIn_IsHighRisk()
    {
        var entry = Assert.Single(Scanner(new FakeSource(Run("Helper",
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="))).Scan().Entries);

        Assert.Equal(FindingSeverity.High, entry.Severity);
        Assert.Contains(entry.Findings, f => f.Title == "Starts a script");
    }

    [Fact]
    public void SourceFindings_AreKept()
    {
        var hijack = new RawStartupEntry(StartupSource.LaunchHijack, "sethc.exe → debugger", "HKLM\\...", "\"C:\\Program Files\\Good\\good.exe\"",
            SourceFindings: [new(FindingSeverity.High, "Hijacks sethc.exe", "d")]);

        Assert.Equal(FindingSeverity.High, Assert.Single(Scanner(new FakeSource(hijack)).Scan().Entries).Severity);
    }

    [Fact]
    public void BrokenSource_IsReported_OthersStillScanned()
    {
        var scan = Scanner(new BrokenSource(), new FakeSource(Run("Good", "\"C:\\Program Files\\Good\\good.exe\""))).Scan();

        Assert.Single(scan.Entries);
        Assert.Contains(scan.Errors, e => e.Contains("boom"));
    }

    [Fact]
    public void EntryAddedAfterFirstScan_IsNew_AndAlertsOnce()
    {
        var source = new FakeSource(Run("Good", "\"C:\\Program Files\\Good\\good.exe\""));
        var scanner = Scanner(source);
        var engine = new AlertEngine(Core.Services.TemperatureThresholds.Default);

        Assert.Empty(engine.Evaluate(scanner.Scan()));

        source.Entries.Add(Run("Updater", @"C:\Users\me\AppData\Local\Temp\svchost.exe"));
        var scan = scanner.Scan();
        Assert.True(scan.Entries.Single(e => e.Raw.Name == "Updater").IsNew);
        Assert.False(scan.Entries.Single(e => e.Raw.Name == "Good").IsNew);

        var alert = Assert.Single(engine.Evaluate(scan));
        Assert.Equal(AlertKind.Startup, alert.Kind);
        Assert.Equal(FindingSeverity.High, alert.Severity);
        Assert.Contains("Updater", alert.Title);

        Assert.Empty(engine.Evaluate(scanner.Scan()));
    }

    [Fact]
    public void ChangedCommand_CountsAsNewEntry()
    {
        var source = new FakeSource(Run("Helper", "\"C:\\Program Files\\Good\\good.exe\""));
        var scanner = Scanner(source);
        scanner.Scan();

        source.Entries[0] = Run("Helper", @"C:\Users\me\AppData\Local\Temp\svchost.exe");

        Assert.True(Assert.Single(scanner.Scan().Entries).IsNew);
    }
}
