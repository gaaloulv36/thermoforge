using System.Drawing;
using System.Windows;
using Forms = System.Windows.Forms;

namespace ThermoForge.UI.Services;

public enum TrayStatus
{
    Normal,
    Warning,
    Alert,
}

/// <summary>
/// The notification-area icon: shows overall status by colour, a live tooltip, a small menu,
/// and pop-up notifications. WPF has no tray support, so this wraps WinForms' NotifyIcon.
/// </summary>
public sealed class TrayIcon : IDisposable
{
    private readonly Forms.NotifyIcon _icon;
    private readonly Dictionary<TrayStatus, Icon> _icons;
    private readonly Forms.ToolStripMenuItem _pauseItem;
    private TrayStatus _status = (TrayStatus)(-1);
    private Action? _onBalloonClick;

    public TrayIcon()
    {
        var size = Forms.SystemInformation.SmallIconSize;
        _icons = new()
        {
            [TrayStatus.Normal] = LoadIcon("ThermoForge.ico", size),
            [TrayStatus.Warning] = LoadIcon("TrayWarning.ico", size),
            [TrayStatus.Alert] = LoadIcon("TrayAlert.ico", size),
        };

        _pauseItem = new Forms.ToolStripMenuItem("Pause notifications for 1 hour", null, (_, _) => PauseToggled?.Invoke(this, EventArgs.Empty));
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("Open ThermoForge", null, (_, _) => OpenRequested?.Invoke(this, EventArgs.Empty));
        menu.Items.Add(_pauseItem);
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("Exit", null, (_, _) => ExitRequested?.Invoke(this, EventArgs.Empty));

        _icon = new Forms.NotifyIcon { ContextMenuStrip = menu, Text = "ThermoForge" };
        _icon.MouseClick += (_, e) =>
        {
            if (e.Button == Forms.MouseButtons.Left)
                OpenRequested?.Invoke(this, EventArgs.Empty);
        };
        _icon.BalloonTipClicked += (_, _) => (_onBalloonClick ?? (() => OpenRequested?.Invoke(this, EventArgs.Empty)))();
        _icon.BalloonTipClosed += (_, _) => _onBalloonClick = null;
        SetStatus(TrayStatus.Normal);
        _icon.Visible = true;
    }

    public event EventHandler? OpenRequested;
    public event EventHandler? PauseToggled;
    public event EventHandler? ExitRequested;

    public void SetStatus(TrayStatus status)
    {
        if (status == _status)
            return;
        _status = status;
        _icon.Icon = _icons[status];
    }

    /// <summary>Tooltip text; Windows truncates it at 127 characters.</summary>
    public void SetText(string text) => _icon.Text = text.Length > 127 ? text[..126] + "…" : text;

    public void SetPaused(bool paused) =>
        _pauseItem.Text = paused ? "Resume notifications" : "Pause notifications for 1 hour";

    /// <param name="onClick">What clicking the notification does; defaults to opening the window.</param>
    public void Notify(string title, string message, bool isWarning, Action? onClick = null)
    {
        _onBalloonClick = onClick;
        _icon.ShowBalloonTip(10_000, title, message, isWarning ? Forms.ToolTipIcon.Warning : Forms.ToolTipIcon.Info);
    }

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
        foreach (var icon in _icons.Values)
            icon.Dispose();
    }

    private static Icon LoadIcon(string name, System.Drawing.Size size)
    {
        var resource = Application.GetResourceStream(new Uri($"pack://application:,,,/Assets/{name}"))
            ?? throw new InvalidOperationException($"Missing tray icon resource {name}.");
        using var stream = resource.Stream;
        return new Icon(stream, size);
    }
}
