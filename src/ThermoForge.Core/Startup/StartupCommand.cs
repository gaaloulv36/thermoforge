namespace ThermoForge.Core.Startup;

/// <summary>
/// Works out which file an auto-start command runs. Commands come in many shapes: quoted or
/// unquoted paths with spaces, environment variables, driver paths like
/// <c>\SystemRoot\System32\drivers\x.sys</c>, bare names found in System32, and
/// <c>rundll32 some.dll,Entry</c> where the DLL is what really runs.
/// </summary>
public sealed class StartupCommand
{
    private readonly string _windowsDir;
    private readonly Func<string, bool> _fileExists;
    private readonly Func<string, string> _expand;

    public StartupCommand(string windowsDirectory, Func<string, bool> fileExists, Func<string, string>? expandEnvironment = null)
    {
        _windowsDir = windowsDirectory.TrimEnd('\\');
        _fileExists = fileExists;
        _expand = expandEnvironment ?? Environment.ExpandEnvironmentVariables;
    }

    public static StartupCommand ForCurrentSystem() =>
        new(Environment.GetFolderPath(Environment.SpecialFolder.Windows), File.Exists);

    public string? ResolveImage(string? command)
    {
        if (string.IsNullOrWhiteSpace(command))
            return null;

        var (program, arguments) = Split(_expand(command.Trim()));
        if (program is null)
            return null;

        program = Resolve(program);
        if (Path.GetFileName(program).Equals("rundll32.exe", StringComparison.OrdinalIgnoreCase))
        {
            // "rundll32.exe C:\x\payload.dll,Start": the DLL is what matters.
            var (dll, _) = Split(arguments.Split(',')[0].Trim());
            if (dll is not null)
                return Resolve(dll);
        }
        return program;
    }

    /// <summary>Splits off the program, trying longer and longer unquoted prefixes for paths with spaces.</summary>
    private (string? Program, string Arguments) Split(string command)
    {
        if (command.Length == 0)
            return (null, "");

        if (command[0] == '"')
        {
            var end = command.IndexOf('"', 1);
            return end < 0
                ? (command[1..], "")
                : (command[1..end], command[(end + 1)..].Trim());
        }

        var parts = command.Split(' ');
        for (var count = 1; count <= parts.Length; count++)
        {
            var candidate = string.Join(' ', parts[..count]);
            if (Exists(Resolve(candidate)))
                return (candidate, string.Join(' ', parts[count..]).Trim());
        }
        return (parts[0], string.Join(' ', parts[1..]).Trim());
    }

    private bool Exists(string path) => _fileExists(path);

    /// <summary>Turns the many path spellings Windows accepts into an ordinary absolute path.</summary>
    private string Resolve(string path)
    {
        path = path.Trim().Trim('"');
        if (path.StartsWith(@"\??\", StringComparison.Ordinal) || path.StartsWith(@"\\?\", StringComparison.Ordinal))
            path = path[4..];
        if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            path = _windowsDir + path[11..];
        else if (path.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase)
                 || path.StartsWith(@"SysWOW64\", StringComparison.OrdinalIgnoreCase))
            path = $@"{_windowsDir}\{path}";

        if (Path.IsPathFullyQualified(path))
            return WithExeExtension(path);

        // A bare name like "ctfmon.exe" or "explorer": Windows looks in System32, then the Windows folder.
        foreach (var directory in new[] { $@"{_windowsDir}\System32", _windowsDir })
        {
            var candidate = WithExeExtension(Path.Combine(directory, path));
            if (Exists(candidate))
                return candidate;
        }
        return path;
    }

    private string WithExeExtension(string path) =>
        Path.HasExtension(path) || !Exists(path + ".exe") ? path : path + ".exe";
}
