namespace ThermoForge.Core.Processes;

/// <summary>
/// Combines a process's findings into one 0–100 score, so several weak signals can add up
/// to a strong one (e.g. unsigned + busy while you're away + odd command line).
/// </summary>
public static class RiskScore
{
    public const int Max = 100;

    /// <summary>Score at or above which a process counts as Medium / High risk.</summary>
    public const int MediumThreshold = 30;
    public const int HighThreshold = 60;

    public static int Points(FindingSeverity severity) => severity switch
    {
        FindingSeverity.High => HighThreshold,
        FindingSeverity.Medium => MediumThreshold,
        FindingSeverity.Low => 10,
        _ => 0,
    };

    public static int From(IEnumerable<ProcessFinding> findings) =>
        Math.Min(Max, findings.Sum(f => Points(f.Severity)));

    public static FindingSeverity Level(int score) => score switch
    {
        >= HighThreshold => FindingSeverity.High,
        >= MediumThreshold => FindingSeverity.Medium,
        > 0 => FindingSeverity.Low,
        _ => FindingSeverity.None,
    };
}
