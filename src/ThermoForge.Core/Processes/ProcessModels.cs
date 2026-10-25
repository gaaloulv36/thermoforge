namespace ThermoForge.Core.Processes;

/// <summary>Process facts as reported by Windows, before any analysis.</summary>
/// <param name="Path">Null when Windows denies access (typically elevated/system processes when not running as admin).</param>
public sealed record RawProcess(
    int Pid,
    int ParentPid,
    string Name,
    string? Path,
    string? CommandLine,
    DateTime? StartTime);

public enum SignatureStatus
{
    Unknown,
    Signed,
    Unsigned,
    Invalid,
}

/// <param name="Signer">Certificate subject name (e.g. "Microsoft Windows"), when signed.</param>
/// <param name="Detail">Why verification failed, or how it succeeded (e.g. via a Windows catalog).</param>
public sealed record SignatureInfo(SignatureStatus Status, string? Signer, string? Detail)
{
    public static SignatureInfo Unknown(string detail) => new(SignatureStatus.Unknown, null, detail);
}

/// <summary>Per-file facts that don't change while the file is unchanged, so they are cached.</summary>
public sealed record FileMetadata(SignatureInfo Signature, string? Description, string? Company);

public enum FindingSeverity
{
    None,
    Low,
    Medium,
    High,
}

/// <summary>One suspicious trait of a process, with a plain-language explanation.</summary>
public sealed record ProcessFinding(FindingSeverity Severity, string Title, string Detail);

public sealed record ProcessInfo(
    RawProcess Process,
    RawProcess? Parent,
    double CpuPercent,
    long WorkingSetBytes,
    FileMetadata? File,
    IReadOnlyList<ProcessFinding> Findings)
{
    public FindingSeverity Severity =>
        Findings.Count == 0 ? FindingSeverity.None : Findings.Max(f => f.Severity);
}

public sealed record ProcessSnapshot(DateTime Timestamp, IReadOnlyList<ProcessInfo> Processes);
