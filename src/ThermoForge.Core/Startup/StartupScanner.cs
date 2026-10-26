using ThermoForge.Core.Platform;
using ThermoForge.Core.Processes;

namespace ThermoForge.Core.Startup;

/// <summary>
/// Reads every auto-start location, works out which file each entry runs, and checks it with
/// the same rules as running processes, plus checks that only make sense for auto-start
/// entries (missing files, scripts started at sign-in). Call <see cref="Scan"/> from one thread at a time.
/// </summary>
public sealed class StartupScanner
{
    private static readonly HashSet<string> ScriptHosts = new(StringComparer.OrdinalIgnoreCase)
        { "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "cmd.exe" };

    /// <summary>
    /// Where a script at sign-in is unusual enough to mention. Scheduled tasks run scripts all the
    /// time (vendor and Windows maintenance); for those only the command-line rules apply.
    /// </summary>
    private static readonly HashSet<StartupSource> SignInSources = [StartupSource.RunKey, StartupSource.StartupFolder];

    /// <summary>Command shells and script hosts: their signature says nothing about the script they run.</summary>
    public static bool IsScriptHost(string? path) => path is not null && ScriptHosts.Contains(Path.GetFileName(path));

    private readonly IReadOnlyList<IStartupSource> _sources;
    private readonly StartupCommand _command;
    private readonly ProcessAnalyzer _analyzer;
    private readonly TrustStore _trust;
    private readonly StartupBaseline _baseline;
    private readonly Func<string, bool> _fileExists;
    private readonly Func<string, FileMetadata> _metadata;
    private readonly string _elevation;

    public StartupScanner(
        IReadOnlyList<IStartupSource> sources,
        StartupCommand command,
        ProcessAnalyzer analyzer,
        TrustStore trust,
        StartupBaseline baseline,
        Func<string, bool>? fileExists = null,
        Func<string, FileMetadata>? metadata = null,
        bool? isAdministrator = null)
    {
        _sources = sources;
        _command = command;
        _analyzer = analyzer;
        _trust = trust;
        _baseline = baseline;
        _fileExists = fileExists ?? File.Exists;
        _metadata = metadata ?? new FileMetadataCache().Get;
        // Admin rights reveal entries Windows otherwise hides; each level keeps its own baseline.
        _elevation = (isAdministrator ?? SystemEnvironment.IsAdministrator()) ? "admin" : "user";
    }

    public static StartupScanner ForCurrentSystem(TrustStore trust) => new(
        [new RunKeySource(), new StartupFolderSource(), new ScheduledTaskSource(), new ServiceSource(),
         new WinlogonSource(), new LaunchHijackSource(), new WmiSubscriptionSource()],
        StartupCommand.ForCurrentSystem(),
        ProcessAnalyzer.ForCurrentSystem(),
        trust,
        new StartupBaseline(StartupBaseline.DefaultPath));

    public StartupScan Scan()
    {
        var errors = new List<string>();
        var raws = new List<(RawStartupEntry Raw, string Context)>();
        var complete = new HashSet<string>();
        foreach (var source in _sources)
        {
            var context = $"{source.GetType().Name}|{_elevation}";
            var sourceErrors = new List<string>();
            try
            {
                raws.AddRange(source.Read(sourceErrors).Select(raw => (raw, context)));
            }
            catch (Exception ex)
            {
                // One unreadable source must not hide the others.
                sourceErrors.Add($"{source.GetType().Name.Replace("Source", "")}: {ex.Message}");
            }

            if (sourceErrors.Count == 0)
                complete.Add(context);
            errors.AddRange(sourceErrors);
        }

        var seen = _baseline.Observe(raws.Select(r => (r.Raw.Id, r.Context)), complete, DateTime.UtcNow);
        var entries = raws.Select(r => Analyze(r.Raw, seen[r.Raw.Id])).ToList();
        return new StartupScan(DateTime.Now, entries, errors);
    }

    private StartupEntry Analyze(RawStartupEntry raw, StartupBaseline.Observation seen)
    {
        var image = raw.ImagePath ?? _command.ResolveImage(raw.Command);
        var missing = image is not null && Path.IsPathFullyQualified(image) && !_fileExists(image);
        var file = image is not null && !missing && Path.IsPathFullyQualified(image) ? _metadata(image) : null;

        var findings = new List<ProcessFinding>(raw.SourceFindings ?? []);
        if (missing)
        {
            findings.Add(new(FindingSeverity.Low, "Points to a missing file",
                $"{image} doesn't exist. Usually a leftover from an uninstalled program, but malware sometimes deletes its file and recreates it later."));
        }
        else if (image is not null)
        {
            var asProcess = new RawProcess(0, 0, Path.GetFileName(image), Path.IsPathFullyQualified(image) ? image : null, raw.Command, null);
            findings.AddRange(_analyzer.Analyze(asProcess, null, file?.Signature));

            if (SignInSources.Contains(raw.Source) && IsScriptHost(image))
                findings.Add(new(FindingSeverity.Low, "Starts a script",
                    "Runs a command shell or script host automatically. Common for admin tools, but check what the command does."));
        }

        return new StartupEntry(
            raw,
            image,
            missing,
            file,
            findings,
            _trust.IsTrusted(file is null ? null : image),
            seen.FirstSeenUtc.ToLocalTime(),
            seen.IsNew);
    }
}
