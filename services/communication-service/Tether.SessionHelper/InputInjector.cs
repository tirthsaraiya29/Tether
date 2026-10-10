using System;
using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Tether.SessionHelper;

/// <summary>
/// Wraps user32!SendInput for input injection from an interactive-session process.
/// Must only be invoked from Session 1+ (a process running in the logged-on user's desktop).
/// </summary>
internal sealed class InputInjector
{
    // Packet wire constants (mirrors InputModels.kt).
    private const byte PacketTypeInputEvent = 0x05;

    private const byte SubtypeRelativeMove = 0x01;
    private const byte SubtypeButtonState = 0x02;
    private const byte SubtypeScrollDelta = 0x03;
    private const byte SubtypeVirtualKey = 0x04;
    private const byte SubtypeUnicodeChar = 0x05;

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

    // One reusable INPUT per calling thread. SendInput copies the data, so reuse is safe.
    [ThreadStatic] private static INPUT[]? _tlsBuffer;

    /// <summary>
    /// Parse a single wire frame and dispatch it. Returns true if the frame was a valid input frame.
    /// </summary>
    public bool Handle(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 2) return false;
        if (frame[0] != PacketTypeInputEvent) return false;

        byte subtype = frame[1];
        var payload = frame[2..];

        switch (subtype)
        {
            case SubtypeRelativeMove:
                if (payload.Length < 4) return false;
                HandleRelativeMove(
                    BinaryPrimitives.ReadInt16BigEndian(payload[..2]),
                    BinaryPrimitives.ReadInt16BigEndian(payload[2..4]));
                return true;

            case SubtypeButtonState:
                if (payload.Length < 2) return false;
                HandleButton(payload[0], payload[1]);
                return true;

            case SubtypeScrollDelta:
                if (payload.Length < 2) return false;
                HandleScroll(BinaryPrimitives.ReadInt16BigEndian(payload[..2]));
                return true;

            case SubtypeVirtualKey:
                if (payload.Length < 3) return false;
                HandleVirtualKey(
                    BinaryPrimitives.ReadUInt16BigEndian(payload[..2]),
                    payload[2]);
                return true;

            case SubtypeUnicodeChar:
                if (payload.Length < 2) return false;
                HandleUnicode(BinaryPrimitives.ReadUInt16BigEndian(payload[..2]));
                return true;

            default:
                Console.Error.WriteLine($"InputInjector: unknown subtype 0x{subtype:X2}");
                return false;
        }
    }

    private static INPUT[] Buffer()
    {
        var b = _tlsBuffer;
        if (b is null)
        {
            b = new INPUT[1];
            _tlsBuffer = b;
        }
        return b;
    }

    private void Dispatch(uint type, in MOUSEINPUT mi)
    {
        var buf = Buffer();
        buf[0].type = type;
        buf[0].u.mi = mi;
        Send(buf);
    }

    private void Dispatch(uint type, in KEYBDINPUT ki)
    {
        var buf = Buffer();
        buf[0].type = type;
        buf[0].u.ki = ki;
        Send(buf);
    }

    private void Send(INPUT[] buf)
    {
        uint sent = SendInput(1, buf, Marshal.SizeOf<INPUT>());
        if (sent != 1)
        {
            int err = Marshal.GetLastWin32Error();
            Console.Error.WriteLine($"InputInjector: SendInput returned {sent}, GetLastError={err}");
        }
    }

    private void HandleRelativeMove(short dx, short dy)
    {
        var mi = new MOUSEINPUT
        {
            dx = dx,
            dy = dy,
            mouseData = 0,
            dwFlags = MOUSEEVENTF_MOVE,
            time = 0,
            dwExtraInfo = IntPtr.Zero
        };
        Dispatch(INPUT_MOUSE, in mi);
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

        var mi = new MOUSEINPUT
        {
            dx = 0,
            dy = 0,
            mouseData = 0,
            dwFlags = flag,
            time = 0,
            dwExtraInfo = IntPtr.Zero
        };
        Dispatch(INPUT_MOUSE, in mi);
    }

    private void HandleScroll(short delta)
    {
        var mi = new MOUSEINPUT
        {
            dx = 0,
            dy = 0,
            mouseData = unchecked((uint)(delta * WHEEL_DELTA)),
            dwFlags = MOUSEEVENTF_WHEEL,
            time = 0,
            dwExtraInfo = IntPtr.Zero
        };
        Dispatch(INPUT_MOUSE, in mi);
    }

    private void HandleVirtualKey(ushort vk, byte flags)
    {
        uint dwFlags = 0;
        if (flags == KeyStateUp) dwFlags |= KEYEVENTF_KEYUP;
        if (flags == KeyStateExtended) dwFlags |= KEYEVENTF_EXTENDEDKEY;

        var ki = new KEYBDINPUT
        {
            wVk = vk,
            wScan = 0,
            dwFlags = dwFlags,
            time = 0,
            dwExtraInfo = IntPtr.Zero
        };
        Dispatch(INPUT_KEYBOARD, in ki);
    }

    private void HandleUnicode(ushort utf16Char)
    {
        // Fire KEYEVENTF_UNICODE down+up so it works regardless of the active input language.
        var down = new KEYBDINPUT
        {
            wVk = 0,
            wScan = utf16Char,
            dwFlags = KEYEVENTF_UNICODE,
            time = 0,
            dwExtraInfo = IntPtr.Zero
        };
        Dispatch(INPUT_KEYBOARD, in down);

        var up = new KEYBDINPUT
        {
            wVk = 0,
            wScan = utf16Char,
            dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP,
            time = 0,
            dwExtraInfo = IntPtr.Zero
        };
        Dispatch(INPUT_KEYBOARD, in up);
    }

    // ---------- P/Invoke ----------

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint SendInput(uint nInputs, [In] INPUT[] pInputs, int cbSize);

    [StructLayout(LayoutKind.Sequential)]
    private struct INPUT
    {
        public uint type;
        public InputUnion u;
    }

    // On x64 the union starts at offset 8 (after type + 4 bytes padding),
    // because MOUSEINPUT contains an IntPtr (ULONG_PTR) requiring 8-byte alignment.
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