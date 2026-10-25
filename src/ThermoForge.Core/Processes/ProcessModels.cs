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

/// <param name="GpuPercent">Busiest GPU engine used by the process, like Task Manager's GPU column.</param>
/// <param name="IsTrusted">The user marked this exact file as known-good; its findings are shown but not scored.</param>
public sealed record ProcessInfo(
    RawProcess Process,
    RawProcess? Parent,
    double CpuPercent,
    double GpuPercent,
    long WorkingSetBytes,
    FileMetadata? File,
    IReadOnlyList<ProcessFinding> Findings,
    bool IsTrusted = false)
{
    /// <summary>0–100; see <see cref="RiskScore"/>.</summary>
    public int Risk => IsTrusted ? 0 : RiskScore.From(Findings);

    public FindingSeverity Severity => RiskScore.Level(Risk);
}

public sealed record ProcessSnapshot(DateTime Timestamp, IReadOnlyList<ProcessInfo> Processes);
