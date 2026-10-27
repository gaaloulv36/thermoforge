using System.Runtime.InteropServices;

namespace ThermoForge.UI.Services;

/// <summary>
/// Gives the window's title bar the app's obsidian colour instead of the Windows accent colour.
/// Windows 11 honours the caption colour; Windows 10 (1809+) gets its dark title bar. Older
/// versions ignore both, which is harmless.
/// </summary>
public static class DarkTitleBar
{
    private const int UseImmersiveDarkMode = 20;
    private const int CaptionColor = 35;
    private const int TextColor = 36;

    public static void Apply(IntPtr hwnd)
    {
        var on = 1;
        DwmSetWindowAttribute(hwnd, UseImmersiveDarkMode, ref on, sizeof(int));

        // COLORREF is 0x00BBGGRR: obsidian #090D16 and text #F8FAFC.
        var caption = 0x00160D09;
        var text = 0x00FCFAF8;
        DwmSetWindowAttribute(hwnd, CaptionColor, ref caption, sizeof(int));
        DwmSetWindowAttribute(hwnd, TextColor, ref text, sizeof(int));
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
}
