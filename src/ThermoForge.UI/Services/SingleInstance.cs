using System.Runtime.InteropServices;
using System.Threading;

namespace ThermoForge.UI.Services;

/// <summary>
/// Keeps one ThermoForge per Windows session. A second launch (Start menu, desktop icon) asks
/// the running one to show its window and exits. Works across elevation: a normal launch can
/// still reach a copy started with admin rights by the logon task.
/// </summary>
public sealed class SingleInstance : IDisposable
{
    private const string MutexName = @"Local\ThermoForge.Instance";
    private const uint MsgfltAllow = 1;
    private const int AsfwAny = -1;
    private static readonly IntPtr HwndBroadcast = new(0xFFFF);

    /// <summary>Window message the first instance listens for to show itself.</summary>
    public static readonly uint ShowMessage = RegisterWindowMessage("ThermoForge.ShowWindow");

    private Mutex? _mutex;
    private bool _owned;

    /// <param name="wait">How long to wait for a closing instance (e.g. one restarting as administrator).</param>
    /// <returns>False when another instance is running.</returns>
    public bool TryAcquire(TimeSpan wait)
    {
        try
        {
            _mutex = new Mutex(false, MutexName);
        }
        catch (UnauthorizedAccessException)
        {
            // Created by an elevated instance, so this (unelevated) one can't even open it.
            return false;
        }

        try
        {
            _owned = _mutex.WaitOne(wait);
        }
        catch (AbandonedMutexException)
        {
            _owned = true; // The previous instance crashed; take over.
        }
        return _owned;
    }

    /// <summary>Asks the running instance to show its window.</summary>
    public static void SignalFirstInstance()
    {
        // Let the running instance bring its window to the front; Windows otherwise blocks it.
        AllowSetForegroundWindow(AsfwAny);
        PostMessage(HwndBroadcast, ShowMessage, IntPtr.Zero, IntPtr.Zero);
    }

    /// <summary>Lets <see cref="ShowMessage"/> through to an elevated window from unelevated senders.</summary>
    public static void AllowShowMessage(IntPtr hwnd) => ChangeWindowMessageFilterEx(hwnd, ShowMessage, MsgfltAllow, IntPtr.Zero);

    /// <summary>Call on the thread that acquired it (the UI thread).</summary>
    public void Dispose()
    {
        if (_owned)
            _mutex!.ReleaseMutex();
        _mutex?.Dispose();
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint RegisterWindowMessage(string message);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool AllowSetForegroundWindow(int processId);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool PostMessage(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool ChangeWindowMessageFilterEx(IntPtr hwnd, uint message, uint action, IntPtr changeFilterStruct);
}
