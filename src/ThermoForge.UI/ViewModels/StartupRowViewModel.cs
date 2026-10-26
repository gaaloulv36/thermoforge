using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using ThermoForge.Core.Alerts;
using ThermoForge.Core.Processes;
using ThermoForge.Core.Startup;

namespace ThermoForge.UI.ViewModels;

public sealed partial class StartupRowViewModel : ObservableObject
{
    public StartupRowViewModel(StartupEntry entry)
    {
        Update(entry);
    }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(Name), nameof(Kind), nameof(Location), nameof(CommandText), nameof(PathText),
        nameof(Description), nameof(CanToggle), nameof(StateText), nameof(ToggleText), nameof(Publisher),
        nameof(SignatureText), nameof(Findings), nameof(HasFindings), nameof(FindingsSummary), nameof(Risk),
        nameof(Severity), nameof(IsFlagged), nameof(SeverityText), nameof(RiskText), nameof(IsTrusted),
        nameof(TrustButtonText), nameof(IsNew), nameof(FirstSeenText), nameof(IsMicrosoft), nameof(Path))]
    private StartupEntry _entry = null!;

    public RawStartupEntry Raw => Entry.Raw;
    public string Name => Raw.Name;
    public string Kind => AlertEngine.Describe(Raw.Source);
    public string Location => Raw.Location;
    public string CommandText => Raw.Command ?? "(none)";
    public string? Path => Entry.FileMissing ? null : Entry.ImagePath;
    public string PathText => Entry.ImagePath is null ? "Could not work out which file this runs."
        : Entry.FileMissing ? $"{Entry.ImagePath} (missing)" : Entry.ImagePath;
    public string Description => Raw.Description ?? Entry.File?.Description ?? "";
    public bool CanToggle => StartupControl.CanToggle(Raw);
    public string StateText => Raw.Enabled ? "On" : "Off";
    public string ToggleText => Raw.Enabled ? "Turn off" : "Turn on";

    public string Publisher => Entry.File?.Signature.Status switch
    {
        SignatureStatus.Signed => Entry.File.Signature.Signer ?? Entry.File.Company ?? "Store package",
        SignatureStatus.Unsigned => Entry.File.Company is { } company ? $"{company} (unverified)" : "Unsigned",
        SignatureStatus.Invalid => "Invalid signature",
        null => "",
        _ => Entry.File.Company ?? "",
    };

    public string SignatureText => Entry.File?.Signature switch
    {
        null => Entry.FileMissing ? "The file doesn't exist." : "Signature not checked.",
        { Status: SignatureStatus.Signed } s => $"Signed by {s.Signer ?? "a verified publisher"}" + (s.Detail is { } how ? $" ({how})" : ""),
        { Status: SignatureStatus.Unsigned } => "Not digitally signed",
        { Status: SignatureStatus.Invalid } s => $"Invalid signature: {s.Detail}",
        var s => $"Signature could not be checked: {s.Detail}",
    };

    /// <summary>
    /// Signed by Microsoft with nothing to report: hidden by default to keep the list short.
    /// Never for cmd/PowerShell/script hosts: Microsoft signed the host, not the script it runs.
    /// </summary>
    public bool IsMicrosoft => Entry.Findings.Count == 0 && !Entry.IsNew && !StartupScanner.IsScriptHost(Entry.ImagePath)
        && Entry.File?.Signature is { Status: SignatureStatus.Signed, Signer: { } signer }
        && signer.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase);

    public IReadOnlyList<ProcessFinding> Findings => Entry.Findings;
    public bool HasFindings => Findings.Count > 0;
    public string FindingsSummary => Findings.Count switch
    {
        0 => "",
        1 => Findings[0].Title,
        _ => $"{Findings.MaxBy(f => f.Severity)!.Title} (+{Findings.Count - 1} more)",
    };

    public int Risk => Entry.Risk;
    public FindingSeverity Severity => Entry.Severity;
    public bool IsFlagged => Severity > FindingSeverity.None;
    public bool IsTrusted => Entry.IsTrusted;
    public bool IsNew => Entry.IsNew;
    public string FirstSeenText => $"First seen {Entry.FirstSeen.ToString("g", CultureInfo.CurrentCulture)}";
    public string SeverityText => IsTrusted ? "Trusted" : Severity == FindingSeverity.None ? "" : $"{Severity} · {Risk}";
    public string RiskText => IsTrusted
        ? "Trusted by you: findings are shown for reference but don't count."
        : Risk == 0 ? "No risk found" : $"Risk score {Risk}/100 ({Severity})";
    public string TrustButtonText => IsTrusted ? "Remove trust" : "Trust this program";

    public void Update(StartupEntry entry) => Entry = entry;
}
