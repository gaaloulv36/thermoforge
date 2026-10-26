using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using ThermoForge.Core.Processes;

namespace ThermoForge.UI.ViewModels;

public sealed partial class ProcessRowViewModel : ObservableObject
{
    public ProcessRowViewModel(ProcessInfo info)
    {
        Raw = info.Process;
        Update(info);
    }

    public RawProcess Raw { get; }
    public int Pid => Raw.Pid;
    public string Name => Raw.Name;
    public string? Path => Raw.Path;
    public string PathText => Raw.Path ?? "Hidden by Windows. Run as administrator to see it.";
    public string CommandLineText => Raw.CommandLine ?? "Hidden by Windows. Run as administrator to see it.";
    public string StartedText => Raw.StartTime?.ToString("g", CultureInfo.CurrentCulture) ?? "Unknown";
    public bool IsCritical => ProcessControl.IsCritical(Raw);

    [ObservableProperty]
    private double _cpuPercent;

    [ObservableProperty]
    private double _gpuPercent;

    [ObservableProperty]
    private long _workingSetBytes;

    [ObservableProperty]
    private string _parentText = "";

    [ObservableProperty]
    private string _description = "";

    [ObservableProperty]
    private string _publisher = "";

    [ObservableProperty]
    private string _signatureText = "";

    [ObservableProperty]
    private IReadOnlyList<ProcessFinding> _findings = [];

    [ObservableProperty]
    private FindingSeverity _severity;

    /// <summary>0–100 combined risk; 0 when trusted.</summary>
    [ObservableProperty]
    private int _risk;

    [ObservableProperty]
    private bool _isTrusted;

    /// <summary>VirusTotal / Defender results, one line each; empty when never checked.</summary>
    [ObservableProperty]
    private string _reputationText = "";

    public string CpuText => CpuPercent.ToString("F1", CultureInfo.CurrentCulture) + " %";

    public string GpuText => GpuPercent < 0.5 ? "" : GpuPercent.ToString("F0", CultureInfo.CurrentCulture) + " %";

    public string MemoryText => WorkingSetBytes >= 1L << 30
        ? (WorkingSetBytes / (double)(1L << 30)).ToString("F2", CultureInfo.CurrentCulture) + " GB"
        : (WorkingSetBytes >> 20).ToString(CultureInfo.CurrentCulture) + " MB";

    public bool IsFlagged => Severity > FindingSeverity.None;

    /// <summary>Has findings, whether or not they count (trusted programs keep theirs for reference).</summary>
    public bool HasFindings => Findings.Count > 0;

    public string SeverityText => IsTrusted ? "Trusted" : Severity == FindingSeverity.None ? "" : $"{Severity} · {Risk}";

    public string RiskText => IsTrusted
        ? "Trusted by you: findings are shown for reference but don't count."
        : Risk == 0 ? "No risk found" : $"Risk score {Risk}/100 ({Severity})";

    public string TrustButtonText => IsTrusted ? "Remove trust" : "Trust this program";

    public string FindingsSummary => Findings.Count switch
    {
        0 => "",
        1 => Findings[0].Title,
        _ => $"{Findings.MaxBy(f => f.Severity)!.Title} (+{Findings.Count - 1} more)",
    };

    public void Update(ProcessInfo info)
    {
        CpuPercent = info.CpuPercent;
        GpuPercent = info.GpuPercent;
        WorkingSetBytes = info.WorkingSetBytes;
        ParentText = info.Parent is { } parent
            ? $"{parent.Name} (PID {parent.Pid})"
            : Raw.ParentPid == 0 ? "None" : $"PID {Raw.ParentPid} (no longer running)";
        Description = info.File?.Description ?? "";
        Publisher = DescribePublisher(info.File);
        SignatureText = DescribeSignature(info.File);

        // Findings rarely change; avoid churning the details pane every poll.
        if (!Findings.SequenceEqual(info.Findings))
            Findings = info.Findings;
        Risk = info.Risk;
        Severity = info.Severity;
        IsTrusted = info.IsTrusted;
        ReputationText = info.Reputation?.Summary ?? "";
    }

    partial void OnCpuPercentChanged(double value) => OnPropertyChanged(nameof(CpuText));

    partial void OnGpuPercentChanged(double value) => OnPropertyChanged(nameof(GpuText));

    partial void OnWorkingSetBytesChanged(long value) => OnPropertyChanged(nameof(MemoryText));

    partial void OnFindingsChanged(IReadOnlyList<ProcessFinding> value)
    {
        OnPropertyChanged(nameof(FindingsSummary));
        OnPropertyChanged(nameof(HasFindings));
    }

    partial void OnSeverityChanged(FindingSeverity value)
    {
        OnPropertyChanged(nameof(IsFlagged));
        OnRiskTextsChanged();
    }

    partial void OnRiskChanged(int value) => OnRiskTextsChanged();

    partial void OnIsTrustedChanged(bool value)
    {
        OnRiskTextsChanged();
        OnPropertyChanged(nameof(TrustButtonText));
    }

    private void OnRiskTextsChanged()
    {
        OnPropertyChanged(nameof(SeverityText));
        OnPropertyChanged(nameof(RiskText));
    }

    private static string DescribePublisher(FileMetadata? file) => file?.Signature.Status switch
    {
        null => "",
        SignatureStatus.Signed => file.Signature.Signer ?? file.Company ?? "Store package",
        SignatureStatus.Unsigned => file.Company is { } company ? $"{company} (unverified)" : "Unsigned",
        SignatureStatus.Invalid => "Invalid signature",
        _ => file.Company ?? "",
    };

    private static string DescribeSignature(FileMetadata? file)
    {
        if (file is null)
            return "Signature unknown: Windows hides this process's file.";

        var signature = file.Signature;
        return signature.Status switch
        {
            SignatureStatus.Signed => $"Signed by {signature.Signer ?? "a verified publisher"}"
                                      + (signature.Detail is { } how ? $" ({how})" : ""),
            SignatureStatus.Unsigned => "Not digitally signed",
            SignatureStatus.Invalid => $"Invalid signature: {signature.Detail}",
            _ => $"Signature could not be checked: {signature.Detail}",
        };
    }
}
