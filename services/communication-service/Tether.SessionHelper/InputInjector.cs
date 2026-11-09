using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Channels;

namespace Tether.SessionHelper;

/// <summary>
/// Wraps user32!SendInput for input injection from an interactive-session process.
/// Dispatches all input events on a dedicated, real-time worker thread associated with
/// the interactive desktop (WinSta0\Default) to eliminate UIPI, thread detachment, and race conditions.
/// </summary>
internal sealed class InputInjector : IDisposable
{
    // Packet wire constants (mirrors InputModels.kt).
    private const byte PacketTypeInputEvent = 0x05;

    private const byte SubtypeRelativeMove = 0x01;
    private const byte SubtypeButtonState = 0x02;
    private const byte SubtypeScrollDelta = 0x03;
    private const byte SubtypeVirtualKey = 0x04;
    private const byte SubtypeUnicodeChar = 0x05;
    private const byte SubtypeAbsoluteMove = 0x06;
    private const uint MOUSEEVENTF_ABSOLUTE = 0x8000;
    private const uint MOUSEEVENTF_VIRTUALDESK = 0x4000;

    private const byte MouseButtonLeft = 0x01;
    private const byte MouseButtonRight = 0x02;
    private const byte MouseButtonMiddle = 0x03;

    private const byte ButtonStateUp = 0x00;
    private const byte ButtonStateDown = 0x01;

    private const byte KeyStateUp = 0x00;
    private const byte KeyStateDown = 0x01;
    private const byte KeyStateExtended = 0x02;

    // Win32 INPUT type values.
    private const uint INPUT_MOUSE = 0;
    private const uint INPUT_KEYBOARD = 1;

    // MOUSEEVENTF_*
    private const uint MOUSEEVENTF_MOVE = 0x0001;
    private const uint MOUSEEVENTF_LEFTDOWN = 0x0002;
    private const uint MOUSEEVENTF_LEFTUP = 0x0004;
    private const uint MOUSEEVENTF_RIGHTDOWN = 0x0008;
    private const uint MOUSEEVENTF_RIGHTUP = 0x0010;
    private const uint MOUSEEVENTF_MIDDLEDOWN = 0x0020;
    private const uint MOUSEEVENTF_MIDDLEUP = 0x0040;
    private const uint MOUSEEVENTF_WHEEL = 0x0800;

    // KEYEVENTF_*
    private const uint KEYEVENTF_EXTENDEDKEY = 0x0001;
    private const uint KEYEVENTF_KEYUP = 0x0002;
    private const uint KEYEVENTF_UNICODE = 0x0004;

    private const int WHEEL_DELTA = 120;

    // Window station and Desktop access flags
    private const uint WINSTA_ALL_ACCESS = 0x037F;
    private const uint DESKTOP_ALL_ACCESS = 0x01FF;
    private const uint DESKTOP_READOBJECTS = 0x0001;

    // Reusable single-slot INPUT array on the dedicated injection thread
    private readonly INPUT[] _inputBuffer = new INPUT[1];

    // Held buttons and keys for tracking and fail-safe release
    private readonly HashSet<byte> _heldButtons = new();
    private readonly HashSet<ushort> _heldKeys = new();
    private readonly object _heldLock = new();

    // High-performance bounded channel for real-time sequential input delivery
    private readonly Channel<byte[]> _inputQueue = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(2048)
    {
        SingleReader = true,
        SingleWriter = false,
        FullMode = BoundedChannelFullMode.DropOldest,
        AllowSynchronousContinuations = true
    });

    private readonly Thread _workerThread;
    private readonly CancellationTokenSource _cts = new();
    private volatile bool _disposed;

    public InputInjector()
    {
        _workerThread = new Thread(ProcessInputWorker)
        {
            Name = "Tether.InputInjectorThread",
            IsBackground = true,
            Priority = ThreadPriority.AboveNormal
        };
        _workerThread.SetApartmentState(ApartmentState.STA);
        _workerThread.Start();
    }

    /// <summary>
    /// Non-blocking enqueue for incoming named pipe frames.
    /// </summary>
    public void Enqueue(byte[] frame)
    {
        if (_disposed || frame.Length < 2) return;
        _inputQueue.Writer.TryWrite(frame);
    }

    /// <summary>
    /// Direct dispatch entry point. Enqueues for sequential injection on the dedicated input thread.
    /// </summary>
    public bool Handle(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 2) return false;
        if (frame[0] != PacketTypeInputEvent) return false;

        Enqueue(frame.ToArray());
        return true;
    }

    private void ProcessInputWorker()
    {
        EnsureDesktopAttached();

        var reader = _inputQueue.Reader;
        var token = _cts.Token;

        while (!token.IsCancellationRequested && !_disposed)
        {
            try
            {
                // Synchronous wait on the dedicated thread ensures minimal latency and CPU efficiency
                if (!reader.WaitToReadAsync(token).AsTask().GetAwaiter().GetResult())
                {
                    break;
                }
                while (reader.TryRead(out var nextFrame))
                {
                    DispatchFrame(nextFrame);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"InputInjector worker error: {ex.Message}");
                EnsureDesktopAttached();
            }
        }

        ReleaseAllHeldInternal();
    }

    private void DispatchFrame(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 2) return;
        if (frame[0] != PacketTypeInputEvent) return;

        // Security safeguard: Never inject inputs while workstation is locked
        if (LockStateDetector.IsLocked())
        {
            ReleaseAllHeldInternal();
            return;
        }

        byte subtype = frame[1];
        var payload = frame[2..];

        switch (subtype)
        {
            case SubtypeAbsoluteMove:
                if (payload.Length < 4) return;
                HandleAbsoluteMove(
                    BinaryPrimitives.ReadUInt16BigEndian(payload[..2]),
                    BinaryPrimitives.ReadUInt16BigEndian(payload[2..4]));
                break;

            case SubtypeRelativeMove:
                if (payload.Length < 4) return;
                HandleRelativeMove(
                    BinaryPrimitives.ReadInt16BigEndian(payload[..2]),
                    BinaryPrimitives.ReadInt16BigEndian(payload[2..4]));
                break;

            case SubtypeButtonState:
                if (payload.Length < 2) return;
                HandleButton(payload[0], payload[1]);
                break;

            case SubtypeScrollDelta:
                if (payload.Length < 2) return;
                HandleScroll(BinaryPrimitives.ReadInt16BigEndian(payload[..2]));
                break;

            case SubtypeVirtualKey:
                if (payload.Length < 3) return;
                HandleVirtualKey(
                    BinaryPrimitives.ReadUInt16BigEndian(payload[..2]),
                    payload[2]);
                break;

            case SubtypeUnicodeChar:
                if (payload.Length < 2) return;
                HandleUnicode(BinaryPrimitives.ReadUInt16BigEndian(payload[..2]));
                break;

            default:
                Console.Error.WriteLine($"InputInjector: unknown subtype 0x{subtype:X2}");
                break;
        }
    }

    private static bool EnsureDesktopAttached()
    {
        try
        {
            // 1. Ensure process window station is WinSta0
            IntPtr hwinsta = OpenWindowStation("WinSta0", false, WINSTA_ALL_ACCESS);
            if (hwinsta != IntPtr.Zero)
            {
                SetProcessWindowStation(hwinsta);
                CloseWindowStation(hwinsta);
            }

            // 2. Open and attach the calling thread to the current input desktop
            IntPtr hDesktop = OpenInputDesktop(0, false, DESKTOP_ALL_ACCESS);
            if (hDesktop == IntPtr.Zero)
            {
                hDesktop = OpenDesktop("Default", 0, false, DESKTOP_ALL_ACCESS);
            }

            if (hDesktop != IntPtr.Zero)
            {
                bool attached = SetThreadDesktop(hDesktop);
                CloseDesktop(hDesktop);
                return attached;
            }
        }
        catch { }
        return false;
    }

    private bool Send(in INPUT input)
    {
        _inputBuffer[0] = input;
        uint sent = SendInput(1, _inputBuffer, Marshal.SizeOf<INPUT>());
        if (sent == 1) return true;

        int err = Marshal.GetLastWin32Error();
        // If access denied or invalid desktop handle, re-attach and retry SendInput once
        if (err == 5 || err == 6 || err == 1400)
        {
            EnsureDesktopAttached();
            sent = SendInput(1, _inputBuffer, Marshal.SizeOf<INPUT>());
            if (sent == 1) return true;
        }

        return false;
    }

    private void HandleAbsoluteMove(ushort normX, ushort normY)
    {
        var bounds = System.Windows.Forms.SystemInformation.VirtualScreen;
        if (bounds.Width <= 0 || bounds.Height <= 0)
        {
            bounds = System.Windows.Forms.Screen.PrimaryScreen?.Bounds ?? new System.Drawing.Rectangle(0, 0, 1920, 1080);
        }
        int targetX = bounds.Left + (int)((long)normX * bounds.Width / 65535);
        int targetY = bounds.Top + (int)((long)normY * bounds.Height / 65535);
        var input = new INPUT
        {
            type = INPUT_MOUSE,
            u = new InputUnion
            {
                mi = new MOUSEINPUT
                {
                    dx = (int)((long)normX * 65536 / 65535),
                    dy = (int)((long)normY * 65536 / 65535),
                    mouseData = 0,
                    dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                    time = 0,
                    dwExtraInfo = IntPtr.Zero
                }
            }
        };
        if (!Send(in input)) SetCursorPos(targetX, targetY);
    }

    private void HandleRelativeMove(short dx, short dy)
    {
        var input = new INPUT
        {
            type = INPUT_MOUSE,
            u = new InputUnion
            {
                mi = new MOUSEINPUT
                {
                    dx = dx,
                    dy = dy,
                    mouseData = 0,
                    dwFlags = MOUSEEVENTF_MOVE,
                    time = 0,
                    dwExtraInfo = IntPtr.Zero
                }
            }
        };

        if (!Send(in input))
        {
            // Fallback 1: Legacy mouse_event (inserts into system mouse driver stream)
            mouse_event(MOUSEEVENTF_MOVE, unchecked((uint)dx), unchecked((uint)dy), 0, UIntPtr.Zero);

            // Fallback 2: Absolute SetCursorPos bypass (guarantees movement even under UIPI isolation)
            if (GetCursorPos(out POINT pt))
            {
                SetCursorPos(pt.X + dx, pt.Y + dy);
            }
        }
    }

    private void HandleButton(byte buttonId, byte state)
    {
        uint flag;
        bool isDown = state == ButtonStateDown;

        switch (buttonId)
        {
            case MouseButtonLeft:
                flag = isDown ? MOUSEEVENTF_LEFTDOWN : MOUSEEVENTF_LEFTUP;
                break;
            case MouseButtonRight:
                flag = isDown ? MOUSEEVENTF_RIGHTDOWN : MOUSEEVENTF_RIGHTUP;
                break;
            case MouseButtonMiddle:
                flag = isDown ? MOUSEEVENTF_MIDDLEDOWN : MOUSEEVENTF_MIDDLEUP;
                break;
            default:
                Console.Error.WriteLine($"InputInjector: unknown mouse button 0x{buttonId:X2}");
                return;
        }

        lock (_heldLock)
        {
            if (isDown) _heldButtons.Add(buttonId); else _heldButtons.Remove(buttonId);
        }

        var input = new INPUT
        {
            type = INPUT_MOUSE,
            u = new InputUnion
            {
                mi = new MOUSEINPUT
                {
                    dx = 0,
                    dy = 0,
                    mouseData = 0,
                    dwFlags = flag,
                    time = 0,
                    dwExtraInfo = IntPtr.Zero
                }
            }
        };

        if (!Send(in input))
        {
            mouse_event(flag, 0, 0, 0, UIntPtr.Zero);
        }
    }

    private void HandleScroll(short delta)
    {
        uint wheelData = unchecked((uint)(delta * WHEEL_DELTA));
        var input = new INPUT
        {
            type = INPUT_MOUSE,
            u = new InputUnion
            {
                mi = new MOUSEINPUT
                {
                    dx = 0,
                    dy = 0,
                    mouseData = wheelData,
                    dwFlags = MOUSEEVENTF_WHEEL,
                    time = 0,
                    dwExtraInfo = IntPtr.Zero
                }
            }
        };

        if (!Send(in input))
        {
            mouse_event(MOUSEEVENTF_WHEEL, 0, 0, wheelData, UIntPtr.Zero);
        }
    }

    private static bool IsExtendedKey(ushort vk) => vk switch
    {
        0x21 or 0x22 or 0x23 or 0x24 or 0x25 or 0x26 or 0x27 or 0x28 or // Prior, Next, End, Home, Left, Up, Right, Down
        0x2D or 0x2E or // Insert, Delete
        0x5B or 0x5C or 0x5D or // LWin, RWin, Apps
        0x6F or 0x90 or // Divide, NumLock
        0xA3 or 0xA5 => true, // RControl, RMenu
        _ => false
    };

    private void HandleVirtualKey(ushort vk, byte flags)
    {
        uint dwFlags = 0;
        bool isDown = flags != KeyStateUp;
        if (flags == KeyStateUp) dwFlags |= KEYEVENTF_KEYUP;
        if (flags == KeyStateExtended || IsExtendedKey(vk)) dwFlags |= KEYEVENTF_EXTENDEDKEY;

        lock (_heldLock)
        {
            if (isDown) _heldKeys.Add(vk); else _heldKeys.Remove(vk);
        }

        var input = new INPUT
        {
            type = INPUT_KEYBOARD,
            u = new InputUnion
            {
                ki = new KEYBDINPUT
                {
                    wVk = vk,
                    wScan = 0,
                    dwFlags = dwFlags,
                    time = 0,
                    dwExtraInfo = IntPtr.Zero
                }
            }
        };

        if (!Send(in input))
        {
            byte bVk = (byte)(vk & 0xFF);
            uint bFlags = (flags == KeyStateUp) ? 0x0002u : 0u;
            if (flags == KeyStateExtended || IsExtendedKey(vk)) bFlags |= 0x0001u;
            keybd_event(bVk, 0, bFlags, UIntPtr.Zero);
        }
    }

    private void HandleUnicode(ushort utf16Char)
    {
        if (utf16Char == '\n' || utf16Char == '\r')
        {
            HandleVirtualKey(0x0D, KeyStateDown);
            HandleVirtualKey(0x0D, KeyStateUp);
            return;
        }

        var down = new INPUT
        {
            type = INPUT_KEYBOARD,
            u = new InputUnion
            {
                ki = new KEYBDINPUT
                {
                    wVk = 0,
                    wScan = utf16Char,
                    dwFlags = KEYEVENTF_UNICODE,
                    time = 0,
                    dwExtraInfo = IntPtr.Zero
                }
            }
        };
        Send(in down);

        var up = new INPUT
        {
            type = INPUT_KEYBOARD,
            u = new InputUnion
            {
                ki = new KEYBDINPUT
                {
                    wVk = 0,
                    wScan = utf16Char,
                    dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP,
                    time = 0,
                    dwExtraInfo = IntPtr.Zero
                }
            }
        };
        Send(in up);
    }

    public void ReleaseAllHeld()
    {
        ReleaseAllHeldInternal();
    }

    private void ReleaseAllHeldInternal()
    {
        byte[] buttons;
        ushort[] keys;
        lock (_heldLock)
        {
            buttons = _heldButtons.ToArray();
            _heldButtons.Clear();
            keys = _heldKeys.ToArray();
            _heldKeys.Clear();
        }

        foreach (var b in buttons)
        {
            uint flag = b switch
            {
                MouseButtonLeft => MOUSEEVENTF_LEFTUP,
                MouseButtonRight => MOUSEEVENTF_RIGHTUP,
                MouseButtonMiddle => MOUSEEVENTF_MIDDLEUP,
                _ => 0
            };
            if (flag != 0)
            {
                var input = new INPUT
                {
                    type = INPUT_MOUSE,
                    u = new InputUnion { mi = new MOUSEINPUT { dwFlags = flag } }
                };
                if (!Send(in input))
                {
                    mouse_event(flag, 0, 0, 0, UIntPtr.Zero);
                }
            }
        }

        foreach (var vk in keys)
        {
            uint flags = KEYEVENTF_KEYUP;
            if (IsExtendedKey(vk)) flags |= KEYEVENTF_EXTENDEDKEY;
            var input = new INPUT
            {
                type = INPUT_KEYBOARD,
                u = new InputUnion { ki = new KEYBDINPUT { wVk = vk, dwFlags = flags } }
            };
            if (!Send(in input))
            {
                byte bVk = (byte)(vk & 0xFF);
                keybd_event(bVk, 0, 0x0002u | (IsExtendedKey(vk) ? 0x0001u : 0u), UIntPtr.Zero);
            }
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _inputQueue.Writer.TryComplete();
        try { _cts.Cancel(); } catch { }
        try { _workerThread.Join(500); } catch { }
        _cts.Dispose();
    }

    // ---------- P/Invoke ----------

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint SendInput(uint nInputs, [In] INPUT[] pInputs, int cbSize);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern void mouse_event(uint dwFlags, uint dx, uint dy, uint dwData, UIntPtr dwExtraInfo);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetCursorPos(int X, int Y);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool GetCursorPos(out POINT lpPoint);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr OpenWindowStation(string lpszWinSta, bool fInherit, uint dwDesiredAccess);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetProcessWindowStation(IntPtr hWinSta);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool CloseWindowStation(IntPtr hWinSta);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr OpenInputDesktop(uint dwFlags, bool fInherit, uint dwDesiredAccess);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr OpenDesktop(string lpszDesktop, uint dwFlags, bool fInherit, uint dwDesiredAccess);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetThreadDesktop(IntPtr hDesktop);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool CloseDesktop(IntPtr hDesktop);

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT
    {
        public int X;
        public int Y;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct INPUT
    {
        public uint type;
        public InputUnion u;
    }

    [StructLayout(LayoutKind.Explicit)]
    private struct InputUnion
    {
        [FieldOffset(0)] public MOUSEINPUT mi;
        [FieldOffset(0)] public KEYBDINPUT ki;
        [FieldOffset(0)] public HARDWAREINPUT hi;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MOUSEINPUT
    {
        public int dx;
        public int dy;
        public uint mouseData;
        public uint dwFlags;
        public uint time;
        public IntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct KEYBDINPUT
    {
        public ushort wVk;
        public ushort wScan;
        public uint dwFlags;
        public uint time;
        public IntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct HARDWAREINPUT
    {
        public uint uMsg;
        public ushort wParamL;
        public ushort wParamH;
    }
}
