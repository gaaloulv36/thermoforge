using System.Text.RegularExpressions;

namespace TempMonitor.Core.Processes;

/// <summary>
/// Heuristic checks for a single process. Every rule is a well-known malware trait, but each
/// can also have innocent causes, so findings are hints for a human, not verdicts.
/// </summary>
public sealed partial class ProcessAnalyzer
{
    private readonly string _windowsDir;
    private readonly string _system32;
    private readonly string _sysWow64;
    private readonly Dictionary<string, string[]> _expectedDirectories;

    public ProcessAnalyzer(string windowsDirectory)
    {
        _windowsDir = Normalize(windowsDirectory);
        _system32 = Normalize(Path.Combine(windowsDirectory, "System32"));
        _sysWow64 = Normalize(Path.Combine(windowsDirectory, "SysWOW64"));

        string[] systemOnly = [_system32];
        string[] systemOrWow = [_system32, _sysWow64];
        _expectedDirectories = new(StringComparer.OrdinalIgnoreCase)
        {
            ["svchost"] = systemOrWow,
            ["lsass"] = systemOnly,
            ["csrss"] = systemOnly,
            ["smss"] = systemOnly,
            ["wininit"] = systemOnly,
            ["winlogon"] = systemOnly,
            ["services"] = systemOnly,
            ["spoolsv"] = systemOnly,
            ["lsaiso"] = systemOnly,
            ["taskhostw"] = systemOnly,
            ["sihost"] = systemOnly,
            ["fontdrvhost"] = systemOnly,
            ["dwm"] = systemOnly,
            ["conhost"] = systemOnly,
            ["dllhost"] = systemOrWow,
            ["rundll32"] = systemOrWow,
            ["regsvr32"] = systemOrWow,
            ["ctfmon"] = systemOrWow,
            ["runtimebroker"] = systemOnly,
            ["explorer"] = [_windowsDir, _sysWow64],
        };
    }

    public static ProcessAnalyzer ForCurrentSystem() =>
        new(Environment.GetFolderPath(Environment.SpecialFolder.Windows));

    /// <summary>Names malware most often copies or misspells. Short names are left out to avoid false look-alike matches.</summary>
    private static readonly string[] ImpersonationTargets =
        ["svchost", "lsass", "csrss", "winlogon", "services", "wininit", "explorer", "spoolsv", "taskhostw", "dllhost", "conhost", "rundll32"];

    /// <summary>Real Windows names that are one edit away from a target and must not be flagged.</summary>
    private static readonly HashSet<string> KnownGoodNames = new(StringComparer.OrdinalIgnoreCase) { "taskhost", "service" };

    private static readonly HashSet<string> OfficeApps = new(StringComparer.OrdinalIgnoreCase)
        { "winword", "excel", "powerpnt", "outlook", "msaccess", "mspub", "onenote", "visio", "acrord32", "acrobat" };

    private static readonly HashSet<string> Browsers = new(StringComparer.OrdinalIgnoreCase)
        { "chrome", "msedge", "firefox", "brave", "opera", "iexplore" };

    private static readonly HashSet<string> ShellsAndLolbins = new(StringComparer.OrdinalIgnoreCase)
        { "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin" };

    private static readonly HashSet<string> ScriptHosts = new(StringComparer.OrdinalIgnoreCase)
        { "wscript", "cscript", "mshta" };

    private static readonly string[] PowerShells = ["powershell", "pwsh"];

    private static readonly LocationRule[] LocationRules =
    [
        new(RecycleBinPath(), FindingSeverity.High, "the Recycle Bin",
            "Programs never run from the Recycle Bin; malware hides there because people rarely look."),
        new(UserTempPath(), FindingSeverity.Medium, "a temporary folder",
            "Installers unpack here briefly, but anything that keeps running from Temp is a classic malware trait."),
        new(WindowsTempPath(), FindingSeverity.Medium, "the Windows temporary folder",
            "Normal software doesn't keep running from C:\\Windows\\Temp."),
        new(PublicUserPath(), FindingSeverity.Medium, "the Public user folder",
            "C:\\Users\\Public is writable by everyone, which makes it a popular malware drop location."),
        new(AppDataRootExePath(), FindingSeverity.Medium, "the root of AppData",
            "Real apps install into their own subfolder; an .exe sitting directly in AppData is suspicious."),
        new(ProgramDataRootExePath(), FindingSeverity.Medium, "the root of ProgramData",
            "Real apps install into their own subfolder; an .exe sitting directly in ProgramData is suspicious."),
        new(DownloadsPath(), FindingSeverity.Low, "the Downloads folder",
            "Usually just an installer you ran, but worth a look if you don't recognise it."),
    ];

    private static readonly CommandLineRule[] CommandLineRules =
    [
        new(PowerShells, IsEncodedPowerShell, FindingSeverity.High, "Runs hidden (encoded) PowerShell code",
            "The command is Base64-encoded so it can't be read at a glance. Attackers use this to hide what a script does."),
        new(null, cl => DownloadCradle().IsMatch(cl), FindingSeverity.High, "Downloads and runs code from the internet",
            "The command line fetches a script from the web and executes it in memory, a common malware loader pattern."),
        new(PowerShells, IsHiddenWindowPowerShell, FindingSeverity.Medium, "PowerShell with a hidden window",
            "The script deliberately hides its window from the user."),
        new(null, cl => cl.Contains("FromBase64String", StringComparison.OrdinalIgnoreCase), FindingSeverity.Medium,
            "Decodes Base64 data", "Decoding Base64 at run time is often used to unpack hidden payloads."),
        new(PowerShells, cl => ExecutionPolicyBypass().IsMatch(cl), FindingSeverity.Low, "Bypasses the PowerShell execution policy",
            "Common in legitimate admin scripts, but also in malware launching scripts."),
        new(["mshta"], cl => RemoteOrScriptUrl().IsMatch(cl), FindingSeverity.High, "mshta runs remote or inline script",
            "mshta.exe executing a URL or inline script is a well-known way to run malware past security tools."),
        new(["rundll32"], cl => cl.Contains("javascript:", StringComparison.OrdinalIgnoreCase), FindingSeverity.High,
            "rundll32 runs JavaScript", "rundll32 has no legitimate reason to execute JavaScript."),
        new(["certutil"], cl => CertutilAbuse().IsMatch(cl), FindingSeverity.High, "certutil used to download or decode files",
            "certutil is a certificate tool, but attackers abuse it to download and unpack malware."),
        new(["regsvr32"], cl => Regsvr32Abuse().IsMatch(cl), FindingSeverity.High, "regsvr32 loads a remote script",
            "Known as \"Squiblydoo\": regsvr32 fetching a scriptlet from the internet to run code."),
        new(["bitsadmin"], cl => cl.Contains("/transfer", StringComparison.OrdinalIgnoreCase), FindingSeverity.Medium,
            "bitsadmin downloads a file", "BITS transfers are used by Windows Update, but also to fetch malware quietly."),
    ];

    public IReadOnlyList<ProcessFinding> Analyze(RawProcess process, RawProcess? parent, SignatureInfo? signature)
    {
        var findings = new List<ProcessFinding>();
        var name = BaseName(process.Name);

        if (process.Path is { } path)
        {
            CheckMasquerade(name, path, findings);
            CheckLocationAndSignature(path, signature, findings);
        }
        CheckLookalikeName(name, findings);
        if (!string.IsNullOrWhiteSpace(process.CommandLine))
            CheckCommandLine(name, process.CommandLine, findings);
        if (parent is not null)
            CheckParent(BaseName(parent.Name), name, process.Name, parent.Name, findings);

        return findings;
    }

    private void CheckMasquerade(string name, string path, List<ProcessFinding> findings)
    {
        if (!_expectedDirectories.TryGetValue(name, out var expected))
            return;

        var directory = Normalize(Path.GetDirectoryName(path) ?? "");
        if (expected.Contains(directory, StringComparer.OrdinalIgnoreCase))
            return;

        findings.Add(new(FindingSeverity.High, $"Impersonates the Windows process {name}.exe",
            $"The real {name}.exe only runs from {string.Join(" or ", expected)}, but this one runs from {directory}."));
    }

    private static void CheckLocationAndSignature(string path, SignatureInfo? signature, List<ProcessFinding> findings)
    {
        var location = LocationRules.FirstOrDefault(r => r.Pattern.IsMatch(path));
        var status = signature?.Status ?? SignatureStatus.Unknown;

        if (status == SignatureStatus.Invalid)
            findings.Add(new(FindingSeverity.High, "Invalid digital signature",
                $"{signature!.Detail} A broken signature can mean the file was tampered with."));

        if (location is null)
        {
            if (status == SignatureStatus.Unsigned)
                findings.Add(new(FindingSeverity.Low, "Unsigned program",
                    "The file has no digital signature, so its publisher can't be verified. Plenty of small tools are unsigned, but so is most malware."));
            return;
        }

        if (status == SignatureStatus.Unsigned && location.Severity >= FindingSeverity.Medium)
        {
            // The combination is far more telling than either trait alone.
            findings.Add(new(FindingSeverity.High, $"Unsigned program running from {location.Label}",
                $"{location.Explanation} It also has no digital signature to show who made it."));
            return;
        }

        if (status == SignatureStatus.Unsigned)
            findings.Add(new(FindingSeverity.Low, "Unsigned program",
                "The file has no digital signature, so its publisher can't be verified."));

        // A valid signature from a trusted publisher makes an odd location much less worrying.
        var severity = status == SignatureStatus.Signed ? location.Severity - 1 : location.Severity;
        if (severity > FindingSeverity.None)
            findings.Add(new(severity, $"Runs from {location.Label}", location.Explanation));
    }

    private static void CheckLookalikeName(string name, List<ProcessFinding> findings)
    {
        if (name.Length < 5 || KnownGoodNames.Contains(name))
            return;

        foreach (var target in ImpersonationTargets)
        {
            if (!name.Equals(target, StringComparison.OrdinalIgnoreCase) && EditDistance(name, target) == 1)
            {
                findings.Add(new(FindingSeverity.High, $"Name imitates {target}.exe",
                    $"\"{name}.exe\" is one character away from the Windows process \"{target}.exe\", a common trick to blend in."));
                return;
            }
        }
    }

    private static void CheckCommandLine(string name, string commandLine, List<ProcessFinding> findings)
    {
        foreach (var rule in CommandLineRules)
        {
            if ((rule.Processes is null || rule.Processes.Contains(name)) && rule.Matches(commandLine))
                findings.Add(new(rule.Severity, rule.Title, rule.Detail));
        }
    }

    private static void CheckParent(string parent, string child, string childName, string parentName, List<ProcessFinding> findings)
    {
        if (OfficeApps.Contains(parent) && ShellsAndLolbins.Contains(child))
            findings.Add(new(FindingSeverity.High, $"Started by {parentName}",
                $"Office documents launching {childName} is how macro malware typically gets its first foothold."));
        else if (Browsers.Contains(parent) && ScriptHosts.Contains(child))
            findings.Add(new(FindingSeverity.Medium, $"Script host started by {parentName}",
                $"A browser launching {childName} can mean a downloaded script was opened directly."));
    }

    private static bool IsEncodedPowerShell(string commandLine) =>
        EncodedArgument().Matches(commandLine).Any(m =>
            "encodedcommand".StartsWith(m.Groups["flag"].Value, StringComparison.OrdinalIgnoreCase));

    private static bool IsHiddenWindowPowerShell(string commandLine) =>
        WindowStyleArgument().Matches(commandLine).Any(m =>
            "windowstyle".StartsWith(m.Groups["flag"].Value, StringComparison.OrdinalIgnoreCase)
            && "hidden".StartsWith(m.Groups["value"].Value, StringComparison.OrdinalIgnoreCase));

    private static string BaseName(string processName) =>
        Path.GetFileNameWithoutExtension(processName).ToLowerInvariant();

    private static string Normalize(string directory) => directory.TrimEnd('\\');

    /// <summary>Optimal string alignment distance: insertions, deletions, substitutions and adjacent swaps.</summary>
    internal static int EditDistance(string a, string b)
    {
        a = a.ToLowerInvariant();
        b = b.ToLowerInvariant();
        var d = new int[a.Length + 1, b.Length + 1];
        for (var i = 0; i <= a.Length; i++) d[i, 0] = i;
        for (var j = 0; j <= b.Length; j++) d[0, j] = j;

        for (var i = 1; i <= a.Length; i++)
        {
            for (var j = 1; j <= b.Length; j++)
            {
                var cost = a[i - 1] == b[j - 1] ? 0 : 1;
                d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + cost);
                if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1])
                    d[i, j] = Math.Min(d[i, j], d[i - 2, j - 2] + 1);
            }
        }
        return d[a.Length, b.Length];
    }

    private sealed record LocationRule(Regex Pattern, FindingSeverity Severity, string Label, string Explanation);

    /// <param name="Processes">Lower-case base names the rule applies to; null for any process.</param>
    private sealed record CommandLineRule(
        string[]? Processes,
        Func<string, bool> Matches,
        FindingSeverity Severity,
        string Title,
        string Detail);

    private const RegexOptions Options = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

    [GeneratedRegex(@"^[a-z]:\\\$Recycle\.Bin\\", Options)]
    private static partial Regex RecycleBinPath();

    [GeneratedRegex(@"\\AppData\\Local\\Temp\\", Options)]
    private static partial Regex UserTempPath();

    [GeneratedRegex(@"^[a-z]:\\Windows\\Temp\\", Options)]
    private static partial Regex WindowsTempPath();

    [GeneratedRegex(@"^[a-z]:\\Users\\Public\\", Options)]
    private static partial Regex PublicUserPath();

    [GeneratedRegex(@"^[a-z]:\\Users\\[^\\]+\\AppData\\(Roaming|Local|LocalLow)\\[^\\]+\.exe$", Options)]
    private static partial Regex AppDataRootExePath();

    [GeneratedRegex(@"^[a-z]:\\ProgramData\\[^\\]+\.exe$", Options)]
    private static partial Regex ProgramDataRootExePath();

    [GeneratedRegex(@"^[a-z]:\\Users\\[^\\]+\\Downloads\\", Options)]
    private static partial Regex DownloadsPath();

    [GeneratedRegex(@"(?:^|\s)[-/](?<flag>e[a-z]*)\s+(?<arg>[a-z0-9+/=]{20,})", Options)]
    private static partial Regex EncodedArgument();

    [GeneratedRegex(@"(?:^|\s)[-/](?<flag>w[a-z]*)\s+(?<value>[a-z]+)", Options)]
    private static partial Regex WindowStyleArgument();

    [GeneratedRegex(@"(iex|invoke-expression).*(downloadstring|downloadfile|invoke-webrequest|iwr\s|net\.webclient|invoke-restmethod|irm\s)|(downloadstring|invoke-webrequest|iwr\s|invoke-restmethod|irm\s).*\|\s*(iex|invoke-expression)", Options)]
    private static partial Regex DownloadCradle();

    [GeneratedRegex(@"(?:^|\s)[-/](ep|ex[a-z]*)\s+bypass\b", Options)]
    private static partial Regex ExecutionPolicyBypass();

    [GeneratedRegex(@"https?:|javascript:|vbscript:", Options)]
    private static partial Regex RemoteOrScriptUrl();

    [GeneratedRegex(@"[-/](urlcache|decode|decodehex)\b", Options)]
    private static partial Regex CertutilAbuse();

    [GeneratedRegex(@"/i:\s*https?:|scrobj\.dll", Options)]
    private static partial Regex Regsvr32Abuse();
}
