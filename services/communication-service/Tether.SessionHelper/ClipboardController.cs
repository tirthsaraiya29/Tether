using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace Tether.SessionHelper;

internal sealed class ClipboardController : NativeWindow, IDisposable
{
    private static readonly IntPtr HWND_MESSAGE = new IntPtr(-3);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool AddClipboardFormatListener(IntPtr hwnd);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool RemoveClipboardFormatListener(IntPtr hwnd);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint SendInput(uint nInputs, [In] INPUT[] pInputs, int cbSize);

    [StructLayout(LayoutKind.Sequential)]
    internal struct INPUT
    {
        public uint type;
        public InputUnion u;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct InputUnion
    {
        [FieldOffset(0)] public MOUSEINPUT mi;
        [FieldOffset(0)] public KEYBDINPUT ki;
        [FieldOffset(0)] public HARDWAREINPUT hi;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MOUSEINPUT
    {
        public int dx;
        public int dy;
        public uint mouseData;
        public uint dwFlags;
        public uint time;
        public IntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct KEYBDINPUT
    {
        public ushort wVk;
        public ushort wScan;
        public uint dwFlags;
        public uint time;
        public IntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct HARDWAREINPUT
    {
        public uint uMsg;
        public ushort wParamL;
        public ushort wParamH;
    }

    private const int WM_CLIPBOARDUPDATE = 0x031D;
    private const ushort VK_CONTROL = 0x11;
    private const ushort VK_C = 0x43;
    private const ushort VK_V = 0x56;
    private const uint KEYEVENTF_KEYUP = 0x0002;

    private readonly Action<string> _onClipboardChanged;
    private string _lastSentHash = string.Empty;
    private bool _disposed;

    public ClipboardController(Action<string> onClipboardChanged)
    {
        _onClipboardChanged = onClipboardChanged;
        var cp = new CreateParams
        {
            Parent = HWND_MESSAGE
        };
        CreateHandle(cp);
        AddClipboardFormatListener(Handle);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try
        {
            if (Handle != IntPtr.Zero)
            {
                RemoveClipboardFormatListener(Handle);
                DestroyHandle();
            }
        }
        catch { }
        try
        {
            Application.ExitThread();
        }
        catch { }
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
        SendKeyCombo(VK_CONTROL, VK_C);
    }

    public static void SimulatePaste()
    {
        SendKeyCombo(VK_CONTROL, VK_V);
    }

    private static void SendKeyCombo(ushort modVk, ushort keyVk)
    {
        var inputs = new INPUT[4];
        inputs[0] = new INPUT { type = 1, u = new InputUnion { ki = new KEYBDINPUT { wVk = modVk } } };
        inputs[1] = new INPUT { type = 1, u = new InputUnion { ki = new KEYBDINPUT { wVk = keyVk } } };
        inputs[2] = new INPUT { type = 1, u = new InputUnion { ki = new KEYBDINPUT { wVk = keyVk, dwFlags = KEYEVENTF_KEYUP } } };
        inputs[3] = new INPUT { type = 1, u = new InputUnion { ki = new KEYBDINPUT { wVk = modVk, dwFlags = KEYEVENTF_KEYUP } } };
        SendInput((uint)inputs.Length, inputs, Marshal.SizeOf<INPUT>());
    }

    private static string ComputeHash(string text)
    {
        byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes(text));
        return Convert.ToHexString(bytes);
    }
}
