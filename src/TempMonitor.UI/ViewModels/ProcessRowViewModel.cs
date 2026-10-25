using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using TempMonitor.Core.Processes;

namespace TempMonitor.UI.ViewModels;

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

    public string CpuText => CpuPercent.ToString("F1", CultureInfo.CurrentCulture) + " %";

    public string MemoryText => WorkingSetBytes >= 1L << 30
        ? (WorkingSetBytes / (double)(1L << 30)).ToString("F2", CultureInfo.CurrentCulture) + " GB"
        : (WorkingSetBytes >> 20).ToString(CultureInfo.CurrentCulture) + " MB";

    public bool IsFlagged => Severity > FindingSeverity.None;

    public string SeverityText => Severity == FindingSeverity.None ? "" : Severity.ToString();

    public string FindingsSummary => Findings.Count switch
    {
        0 => "",
        1 => Findings[0].Title,
        _ => $"{Findings.MaxBy(f => f.Severity)!.Title} (+{Findings.Count - 1} more)",
    };

    public void Update(ProcessInfo info)
    {
        CpuPercent = info.CpuPercent;
        WorkingSetBytes = info.WorkingSetBytes;
        ParentText = info.Parent is { } parent
            ? $"{parent.Name} (PID {parent.Pid})"
            : Raw.ParentPid == 0 ? "None" : $"PID {Raw.ParentPid} (no longer running)";
        Description = info.File?.Description ?? "";
        Publisher = DescribePublisher(info.File);
        SignatureText = DescribeSignature(info.File);

        // Findings rarely change; avoid churning the details pane every poll.
        if (!Findings.SequenceEqual(info.Findings))
        {
            Findings = info.Findings;
            Severity = info.Severity;
        }
    }

    partial void OnCpuPercentChanged(double value) => OnPropertyChanged(nameof(CpuText));

    partial void OnWorkingSetBytesChanged(long value) => OnPropertyChanged(nameof(MemoryText));

    partial void OnFindingsChanged(IReadOnlyList<ProcessFinding> value) => OnPropertyChanged(nameof(FindingsSummary));

    partial void OnSeverityChanged(FindingSeverity value)
    {
        OnPropertyChanged(nameof(IsFlagged));
        OnPropertyChanged(nameof(SeverityText));
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
