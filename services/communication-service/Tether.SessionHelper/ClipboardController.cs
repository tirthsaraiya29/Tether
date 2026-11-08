using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace Tether.SessionHelper;

internal sealed class ClipboardController : Form
{
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool AddClipboardFormatListener(IntPtr hwnd);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool RemoveClipboardFormatListener(IntPtr hwnd);

    [DllImport("user32.dll")]
    private static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);

    private const int WM_CLIPBOARDUPDATE = 0x031D;
    private const byte VK_CONTROL = 0x11;
    private const byte VK_C = 0x43;
    private const byte VK_V = 0x56;
    private const uint KEYEVENTF_KEYUP = 0x0002;

    private readonly Action<string> _onClipboardChanged;
    private string _lastSentHash = string.Empty;

    public ClipboardController(Action<string> onClipboardChanged)
    {
        _onClipboardChanged = onClipboardChanged;
        FormBorderStyle = FormBorderStyle.None;
        ShowInTaskbar = false;
        WindowState = FormWindowState.Minimized;
        Opacity = 0;
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        AddClipboardFormatListener(Handle);
    }

    protected override void OnHandleDestroyed(EventArgs e)
    {
        RemoveClipboardFormatListener(Handle);
        base.OnHandleDestroyed(e);
    }

    protected override void WndProc(ref Message m)
    {
        if (m.Msg == WM_CLIPBOARDUPDATE)
        {
            try
            {
                if (Clipboard.ContainsText())
                {
                    string text = Clipboard.GetText();
                    if (!string.IsNullOrEmpty(text))
                    {
                        string hash = ComputeHash(text);
                        if (!string.Equals(hash, _lastSentHash, StringComparison.OrdinalIgnoreCase))
                        {
                            _lastSentHash = hash;
                            _onClipboardChanged(text);
                        }
                    }
                }
            }
            catch { }
        }
        base.WndProc(ref m);
    }

    public void SetText(string text)
    {
        if (string.IsNullOrEmpty(text)) return;
        _lastSentHash = ComputeHash(text);

        // Run on STA thread to access OLE Clipboard
        var thread = new Thread(() =>
        {
            for (int i = 0; i < 3; i++)
            {
                try
                {
                    Clipboard.SetDataObject(text, true, 5, 100);
                    break;
                }
                catch
                {
                    Thread.Sleep(50);
                }
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join(500);
    }

    public static string GetCurrentText()
    {
        string result = string.Empty;
        var thread = new Thread(() =>
        {
            for (int i = 0; i < 3; i++)
            {
                try
                {
                    if (Clipboard.ContainsText())
                    {
                        result = Clipboard.GetText();
                        break;
                    }
                }
                catch
                {
                    Thread.Sleep(50);
                }
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join(600);
        return result;
    }

    public static void SimulateCopy()
    {
        keybd_event(VK_CONTROL, 0, 0, UIntPtr.Zero);
        keybd_event(VK_C, 0, 0, UIntPtr.Zero);
        keybd_event(VK_C, 0, KEYEVENTF_KEYUP, UIntPtr.Zero);
        keybd_event(VK_CONTROL, 0, KEYEVENTF_KEYUP, UIntPtr.Zero);
    }

    public static void SimulatePaste()
    {
        keybd_event(VK_CONTROL, 0, 0, UIntPtr.Zero);
        keybd_event(VK_V, 0, 0, UIntPtr.Zero);
        keybd_event(VK_V, 0, KEYEVENTF_KEYUP, UIntPtr.Zero);
        keybd_event(VK_CONTROL, 0, KEYEVENTF_KEYUP, UIntPtr.Zero);
    }

    private static string ComputeHash(string text)
    {
        byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes(text));
        return Convert.ToHexString(bytes);
    }
}
