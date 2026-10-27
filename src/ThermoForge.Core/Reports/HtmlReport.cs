using System.Globalization;
using System.Net;
using System.Text;
using ThermoForge.Core.Processes;
using ThermoForge.Core.Reputation;
using ThermoForge.Core.Services;

namespace ThermoForge.Core.Reports;

/// <summary>
/// Renders a <see cref="SecurityReport"/> as one self-contained HTML file (no scripts, no
/// external resources) that opens in any browser and prints cleanly. Every value is
/// HTML-encoded: paths and command lines come from the PC being examined, so they are untrusted.
/// </summary>
public static class HtmlReport
{
    public static string Render(SecurityReport report)
    {
        var html = new StringBuilder();
        html.Append($$"""
            <!doctype html>
            <html lang="en">
            <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>ThermoForge report – {{H(report.ComputerName)}} – {{report.GeneratedAt:yyyy-MM-dd}}</title>
            <style>{{StyleSheet}}</style>
            </head>
            <body>
            <header>
              <div class="brand"><span class="thermo">Thermo</span><span class="forge">Forge</span> <small>by Open Forge Studio</small></div>
              <h1>Security &amp; health report</h1>
              <p>{{H(report.ComputerName)}} · {{H(report.UserName)}} · {{H(report.WindowsVersion)}}{{(report.IsAdministrator ? "" : " · not run as administrator, so some system details were hidden")}}</p>
              <p>Generated {{report.GeneratedAt.ToString("F", CultureInfo.CurrentCulture)}}</p>
            </header>
            <main>
            """);

        // Verdict
        var (verdictClass, verdictText) = report.Verdict switch
        {
            FindingSeverity.High => ("high", "Action needed"),
            FindingSeverity.Medium => ("medium", "Worth a look"),
            _ => ("ok", "No serious problems found"),
        };
        html.Append($"""<section class="verdict {verdictClass}"><h2>{verdictText}</h2>""");
        if (report.Highlights.Count == 0)
            html.Append("<p>Nothing rated Medium or High among running programs, startup entries and connections, and Microsoft Defender reports no problems.</p>");
        else
            html.Append("<ul>").Append(string.Concat(report.Highlights.Select(h => $"<li>{H(h)}</li>"))).Append("</ul>");
        html.Append($"""
            <div class="stats">
              <div><b>{report.ProcessCount}</b>processes</div>
              <div><b>{report.StartupCount}</b>startup entries</div>
              <div><b>{report.ConnectionCount}</b>connections</div>
              <div><b>{report.Processes.Count + report.StartupEntries.Count + report.Connections.Count}</b>flagged items</div>
            </div></section>
            """);

        // Temperatures
        if (report.Temperatures.Count > 0)
        {
            html.Append("<section><h2>Temperatures</h2><table><tr><th>Device</th><th>Sensor</th><th>Now</th><th>Status</th></tr>");
            foreach (var t in report.Temperatures)
                html.Append($"<tr><td>{H(t.Device)}</td><td>{H(t.Sensor)}</td><td>{t.Celsius:F0} °C</td><td class=\"t-{t.Status.ToString().ToLowerInvariant()}\">{t.Status}</td></tr>");
            html.Append("</table></section>");
        }

        Items(html, "Flagged processes", "Running programs with at least one suspicious trait.", report.Processes, "Process");
        Items(html, "Startup entries", "Flagged entries, and entries added in the last week.", report.StartupEntries, "Entry");
        Items(html, "Flagged connections", "Network connections with a suspicious trait.", report.Connections, "Program");

        if (report.InternetTraffic.Count > 0)
        {
            html.Append("<section><h2>Programs talking to the internet</h2><table><tr><th>Program</th><th>Connections</th><th>Servers</th></tr>");
            foreach (var t in report.InternetTraffic)
                html.Append($"<tr><td>{H(t.Program)}</td><td>{t.Connections}</td><td class=\"mono\">{H(string.Join(", ", t.Hosts))}</td></tr>");
            html.Append("</table></section>");
        }

        // Defender
        html.Append("<section><h2>Microsoft Defender</h2>");
        if (report.Defender is { } d)
        {
            html.Append($"""
                <table class="kv">
                <tr><th>Mode</th><td>{H(d.IsActive ? "Active antivirus" : d.RunningMode + " (another antivirus is in charge)")}</td></tr>
                <tr><th>Real-time protection</th><td>{(d.RealTimeProtection ? "On" : "<b class=\"bad\">Off</b>")}</td></tr>
                <tr><th>Definitions updated</th><td>{d.SignaturesUpdated?.ToString("g", CultureInfo.CurrentCulture) ?? "Unknown"}</td></tr>
                <tr><th>Version</th><td>{H(d.Version ?? "Unknown")}</td></tr>
                </table>
                """);
        }
        else
        {
            html.Append("<p>Defender's status couldn't be read (it may be replaced by another antivirus).</p>");
        }
        if (report.DefenderDetections.Count > 0)
        {
            html.Append("<h3>Detection history</h3><table><tr><th>When</th><th>Threat</th><th>Severity</th><th>Status</th><th>Where</th></tr>");
            foreach (var x in report.DefenderDetections)
                html.Append($"<tr><td>{x.Time.ToString("g", CultureInfo.CurrentCulture)}</td><td>{H(x.Threat)}</td><td>{H(x.Severity)}</td><td>{H(x.Status)}</td><td class=\"mono\">{H(string.Join(Environment.NewLine, x.Resources))}</td></tr>");
            html.Append("</table>");
        }
        else
        {
            html.Append("<p>No detections in Defender's history.</p>");
        }
        html.Append("</section>");

        // VirusTotal / Defender file checks
        if (report.FileChecks.Count > 0)
        {
            html.Append("<section><h2>File checks</h2><p class=\"note\">Files checked on request: by SHA-256 on VirusTotal and/or with a Defender scan.</p>");
            html.Append("<table><tr><th>File</th><th>VirusTotal</th><th>Defender</th></tr>");
            foreach (var f in report.FileChecks)
            {
                var vt = f.VirusTotal switch
                {
                    null => "–",
                    { Verdict: VirusTotalVerdict.NotFound } => "Unknown to VirusTotal",
                    var r => $"{r.Malicious} malicious / {r.Engines} engines" + (r.ThreatLabel is { } l ? $" ({l})" : ""),
                };
                var defender = f.Defender switch
                {
                    null => "–",
                    { Threat: { } threat } => threat,
                    _ => "Clean",
                };
                var bad = (f.VirusTotal?.Malicious ?? 0) > 0 || f.Defender?.Threat is not null;
                html.Append($"<tr{(bad ? " class=\"row-high\"" : "")}><td class=\"mono\">{H(f.Path)}<br><small>{H(f.Sha256)}</small></td><td>{H(vt)}</td><td>{H(defender)}</td></tr>");
            }
            html.Append("</table></section>");
        }

        // Alerts
        if (report.Alerts.Count > 0)
        {
            html.Append("<section><h2>Recent alerts</h2><table><tr><th>When</th><th>Alert</th><th>Details</th></tr>");
            foreach (var a in report.Alerts.Take(50))
                html.Append($"<tr><td>{a.Time.ToString("g", CultureInfo.CurrentCulture)}</td><td class=\"sev-{Css(a.Severity)}\">{H(a.Title)}</td><td>{H(a.Message)}</td></tr>");
            html.Append("</table></section>");
        }

        html.Append("""
            <footer>Findings are hints, not verdicts: every rule has innocent explanations. Generated by ThermoForge · Open Forge Studio · gaaloulv36.github.io/open-forge-studio-website</footer>
            </main>
            </body>
            </html>
            """);
        return html.ToString();
    }

    private static void Items(StringBuilder html, string title, string intro, IReadOnlyList<ReportItem> items, string nameHeader)
    {
        html.Append($"<section><h2>{H(title)}</h2>");
        if (items.Count == 0)
        {
            html.Append("<p>None.</p></section>");
            return;
        }
        html.Append($"<p class=\"note\">{H(intro)}</p><table><tr><th>Risk</th><th>{nameHeader}</th><th>Findings</th></tr>");
        foreach (var item in items)
        {
            var risk = item.IsTrusted ? "Trusted" : $"{item.Severity} · {item.Risk}";
            html.Append($"<tr><td class=\"sev-{(item.IsTrusted ? "none" : Css(item.Severity))}\">{H(risk)}</td><td><b>{H(item.Name)}</b><br><small>{H(item.Context)}</small>");
            if (item.Publisher is not null)
                html.Append($"<br><small>{H(item.Publisher)}</small>");
            if (item.Path is not null)
                html.Append($"<br><small class=\"mono\">{H(item.Path)}</small>");
            html.Append("</td><td>");
            foreach (var f in item.Findings.OrderByDescending(f => f.Severity))
                html.Append($"<div class=\"finding\"><span class=\"sev-{Css(f.Severity)}\">{f.Severity} · {H(f.Title)}</span><br><small>{H(f.Detail)}</small></div>");
            html.Append("</td></tr>");
        }
        html.Append("</table></section>");
    }

    private static string Css(FindingSeverity severity) => severity.ToString().ToLowerInvariant();

    private static string H(string text) => WebUtility.HtmlEncode(text);

    private const string StyleSheet = """
        :root { --ink:#1b1f24; --muted:#5d6672; --line:#e3e6ea; --brand:#22D3EE; --high:#d1242f; --medium:#b7791f; --low:#3b6fb6; --ok:#2f8a3e; }
        * { box-sizing:border-box; }
        body { margin:0; font:14px/1.5 "Segoe UI", system-ui, sans-serif; color:var(--ink); background:#f6f7f9; }
        header { background:#090D16; color:#F8FAFC; padding:28px 40px; border-bottom:3px solid #06B6D4; }
        header h1 { margin:6px 0 4px; font-size:26px; font-weight:600; }
        header p { margin:2px 0; color:#a9b2bd; }
        .brand { font-size:20px; } .thermo { font-weight:500; } .forge { font-weight:700; color:var(--brand); }
        .brand { font-family:"JetBrains Mono", Consolas, monospace; } .brand small { color:#94A3B8; font-size:13px; font-family:"Segoe UI", system-ui, sans-serif; }
        main { max-width:1100px; margin:0 auto; padding:24px 40px 40px; }
        section { background:#fff; border:1px solid var(--line); border-radius:10px; padding:18px 22px; margin:0 0 18px; }
        h2 { margin:0 0 10px; font-size:18px; } h3 { font-size:15px; margin:16px 0 8px; }
        .verdict { border-left:6px solid var(--ok); } .verdict.medium { border-left-color:var(--medium); } .verdict.high { border-left-color:var(--high); }
        .verdict.ok h2 { color:var(--ok); } .verdict.medium h2 { color:var(--medium); } .verdict.high h2 { color:var(--high); }
        .stats { display:flex; gap:12px; flex-wrap:wrap; margin-top:12px; }
        .stats div { flex:1 1 140px; background:#f6f7f9; border-radius:8px; padding:10px 14px; color:var(--muted); }
        .stats b { display:block; font-size:22px; color:var(--ink); }
        table { width:100%; border-collapse:collapse; } th, td { text-align:left; vertical-align:top; padding:7px 8px; border-bottom:1px solid var(--line); }
        td:first-child { white-space:nowrap; }
        th { color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.03em; }
        table.kv th { width:220px; text-transform:none; font-size:14px; }
        small { color:var(--muted); } .mono { font-family:Consolas, monospace; font-size:12px; word-break:break-all; white-space:pre-line; }
        .note { color:var(--muted); margin-top:-4px; }
        .finding { margin:0 0 6px; }
        .sev-high, .bad, .t-hot { color:var(--high); font-weight:600; } .sev-medium, .t-warm { color:var(--medium); font-weight:600; }
        .sev-low { color:var(--low); font-weight:600; } .sev-none, .t-normal { color:var(--ok); }
        .row-high td { background:#fdf0f0; }
        footer { color:var(--muted); font-size:12px; text-align:center; margin-top:24px; }
        @media print { body { background:#fff; } section { break-inside:avoid; border-color:#ccc; } header { -webkit-print-color-adjust:exact; print-color-adjust:exact; } }
        @media (max-width:700px) { header, main { padding-left:16px; padding-right:16px; } }
        """;
}
