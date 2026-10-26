using System.Net;
using System.Text.RegularExpressions;
using ThermoForge.Core.Processes;

namespace ThermoForge.Core.Network;

/// <summary>
/// Heuristic checks for a single connection. Like the process rules, each one is a known
/// malware trait with possible innocent causes, so findings are hints, not verdicts.
/// </summary>
public sealed partial class NetworkAnalyzer
{
    /// <summary>
    /// Built-in tools that malware borrows to download its next stage. They have no network
    /// features of their own worth worrying about, except through what they are told to run.
    /// </summary>
    private static readonly Dictionary<string, FindingSeverity> NetworkShyTools = new(StringComparer.OrdinalIgnoreCase)
    {
        ["powershell"] = FindingSeverity.Medium,
        ["pwsh"] = FindingSeverity.Medium,
        ["cmd"] = FindingSeverity.Medium,
        ["wscript"] = FindingSeverity.Medium,
        ["cscript"] = FindingSeverity.Medium,
        ["bitsadmin"] = FindingSeverity.Medium,
        ["rundll32"] = FindingSeverity.Medium,
        ["mshta"] = FindingSeverity.High,
        ["regsvr32"] = FindingSeverity.High,
        ["certutil"] = FindingSeverity.High,
    };

    private static readonly PortRule[] PortRules =
    [
        new([4444, 1337, 31337], FindingSeverity.Medium, "Connects to a port used by hacking tools",
            "Port {0} is the default for Metasploit and other remote-control tools. Legitimate services rarely use it."),
        new([3333, 3334, 5555, 7777, 14433, 14444, 45560, 45700], FindingSeverity.Medium, "Connects to a crypto-mining pool port",
            "Port {0} is commonly used by mining pools (the Stratum protocol). Some games and dev tools use it too."),
        new([9001, 9030, 9050, 9150], FindingSeverity.Medium, "Connects to a Tor port",
            "Port {0} is used by the Tor anonymity network. Fine if you use Tor Browser; malware uses Tor to hide its control server."),
        new([6667, 6697], FindingSeverity.Low, "Uses IRC",
            "Port {0} is IRC, an old chat protocol that botnets still use to receive commands."),
    ];

    public IReadOnlyList<ProcessFinding> Analyze(
        RawConnection connection,
        ConnectionDirection direction,
        RemoteScope scope,
        string? hostName,
        string processName,
        SignatureStatus? signature)
    {
        var findings = new List<ProcessFinding>();
        var unsigned = signature is SignatureStatus.Unsigned or SignatureStatus.Invalid;

        switch (direction)
        {
            case ConnectionDirection.Listening:
                if (unsigned && connection.Protocol == NetProtocol.Tcp && IsAnyAddress(connection.Local.Address))
                    findings.Add(new(FindingSeverity.Low, "Unsigned program accepts connections from the network",
                        $"It listens on TCP port {connection.Local.Port} on every network interface, so other devices can try to connect "
                        + "(if the firewall lets them). Normal for servers and dev tools you installed; a backdoor does the same."));
                break;

            case ConnectionDirection.Incoming when scope == RemoteScope.Internet && unsigned:
                findings.Add(new(FindingSeverity.Medium, "Accepted a connection from the internet",
                    $"Something on the internet ({connection.Remote}) is connected to port {connection.Local.Port} of an unsigned program. "
                    + "Remote-control malware works this way; so do game servers and file-sharing apps."));
                break;

            case ConnectionDirection.Outgoing when scope == RemoteScope.Internet:
                var name = Path.GetFileNameWithoutExtension(processName);
                if (NetworkShyTools.TryGetValue(name, out var toolSeverity))
                    findings.Add(new(toolSeverity, $"{name}.exe connects to the internet",
                        $"Windows' own {name}.exe rarely needs the internet itself. Malware uses it to download and run its next stage. "
                        + "Admin scripts and installers do it too; check the command line on the Processes tab."));

                var port = connection.Remote!.Port;
                if (PortRules.FirstOrDefault(r => r.Ports.Contains(port)) is { } rule)
                    findings.Add(new(rule.Severity, rule.Title, string.Format(rule.Detail, port)));

                if (unsigned)
                    findings.Add(new(FindingSeverity.Low, "Unsigned program talks to the internet",
                        "Its publisher can't be verified, and it sends data to servers outside your network."));
                break;
        }

        if (direction != ConnectionDirection.Listening && hostName is not null && MiningHost().IsMatch(hostName))
            findings.Add(new(FindingSeverity.Medium, "Connects to a crypto-mining pool",
                $"The server's name ({hostName}) belongs to a mining pool. If you don't mine on purpose, this is how hidden miners get paid."));

        return findings;
    }

    /// <summary>A program contacting the same server like clockwork, which is how malware checks in for orders.</summary>
    public static ProcessFinding? Beacon(SignatureStatus? signature, TimeSpan interval, string server)
    {
        // Signed apps check for updates and send telemetry on timers all the time.
        if (signature == SignatureStatus.Signed)
            return null;

        var severity = signature is SignatureStatus.Unsigned or SignatureStatus.Invalid ? FindingSeverity.Medium : FindingSeverity.Low;
        var every = interval.TotalMinutes >= 1 ? $"{interval.TotalMinutes:F0} min" : $"{interval.TotalSeconds:F0} s";
        return new(severity, "Contacts the same server at regular intervals",
            $"It opens a new connection to {server} about every {every}. Malware \"phones home\" like this for instructions; "
            + "so do update checkers and sync tools.");
    }

    private static bool IsAnyAddress(IPAddress address) =>
        address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any);

    private sealed record PortRule(int[] Ports, FindingSeverity Severity, string Title, string Detail);

    [GeneratedRegex(@"(^|[.-])(mining|miningpool|xmr|monero|nicehash|nanopool|2miners|f2pool|ethermine|hashvault|minexmr|supportxmr|moneroocean|herominers|unmineable|c3pool|antpool|viabtc)([.-]|$)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MiningHost();
}
