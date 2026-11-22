using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Channels;
using Tether.Shared.Logging;

namespace Tether.LinuxDaemon.Input;

public sealed class LinuxUinputInjector : IDisposable
{
    private const string UinputPath = "/dev/uinput";

    // Packet wire constants (mirrors InputModels.kt and Tether.SessionHelper).
    public const byte PacketTypeInputEvent = 0x05;
    public const byte SubtypeRelativeMove = 0x01;
    public const byte SubtypeButtonState = 0x02;
    public const byte SubtypeScrollDelta = 0x03;
    public const byte SubtypeVirtualKey = 0x04;
    public const byte SubtypeUnicodeChar = 0x05;
    public const byte SubtypeAbsoluteMove = 0x06;

    public const byte MouseButtonLeft = 0x01;
    public const byte MouseButtonRight = 0x02;
    public const byte MouseButtonMiddle = 0x03;

    public const byte ButtonStateUp = 0x00;
    public const byte ButtonStateDown = 0x01;

    public const byte KeyStateUp = 0x00;
    public const byte KeyStateDown = 0x01;

    // Linux input event types
    private const ushort EV_SYN = 0x00;
    private const ushort EV_KEY = 0x01;
    private const ushort EV_REL = 0x02;
    private const ushort EV_ABS = 0x03;

    private const ushort SYN_REPORT = 0x00;

    // Relative axes
    private const ushort REL_X = 0x00;
    private const ushort REL_Y = 0x01;
    private const ushort REL_HWHEEL = 0x06;
    private const ushort REL_WHEEL = 0x08;

    // Mouse button event codes
    private const ushort BTN_LEFT = 0x110;
    private const ushort BTN_RIGHT = 0x111;
    private const ushort BTN_MIDDLE = 0x112;

    // Linux uinput ioctls (x86_64 / arm64)
    private const ulong UI_SET_EVBIT = 0x40045564;
    private const ulong UI_SET_KEYBIT = 0x40045565;
    private const ulong UI_SET_RELBIT = 0x40045566;
    private const ulong UI_DEV_CREATE = 0x5501;
    private const ulong UI_DEV_DESTROY = 0x5502;
    private const ulong UI_DEV_SETUP = 0x405c5503;

    private const int O_WRONLY = 0x01;
    private const int O_NONBLOCK = 0x800;

    [StructLayout(LayoutKind.Sequential)]
    private struct InputId
    {
        public ushort bustype;
        public ushort vendor;
        public ushort product;
        public ushort version;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    private struct UinputSetup
    {
        public InputId id;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)]
        public string name;
        public uint ff_effects_max;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Timeval
    {
        public IntPtr tv_sec;
        public IntPtr tv_usec;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LinuxInputEvent
    {
        public Timeval time;
        public ushort type;
        public ushort code;
        public int value;
    }

    [DllImport("libc", SetLastError = true)]
    private static extern int open(string pathname, int flags);

    [DllImport("libc", SetLastError = true)]
    private static extern int close(int fd);

    [DllImport("libc", SetLastError = true)]
    private static extern int ioctl(int fd, ulong request, int value);

    [DllImport("libc", SetLastError = true)]
    private static extern int ioctl(int fd, ulong request, ref UinputSetup setup);

    [DllImport("libc", SetLastError = true)]
    private static extern int ioctl(int fd, ulong request);

    [DllImport("libc", SetLastError = true)]
    private static extern IntPtr write(int fd, ref LinuxInputEvent buf, UIntPtr count);

    private readonly ITetherLogger _logger;
    private int _fd = -1;
    private bool _deviceCreated;
    private readonly HashSet<ushort> _heldButtons = new();
    private readonly HashSet<ushort> _heldKeys = new();
    private readonly object _heldLock = new();

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

    // Test hook to observe emitted events without requiring physical uinput access
    public Action<ushort, ushort, int>? OnEventInjected { get; set; }

    public bool IsAvailable => _deviceCreated;

    public LinuxUinputInjector(ITetherLogger logger)
    {
        _logger = logger;

        InitializeUinput();

        _workerThread = new Thread(ProcessInputWorker)
        {
            Name = "Tether.LinuxInputInjectorThread",
            IsBackground = true,
            Priority = ThreadPriority.AboveNormal
        };
        _workerThread.Start();
    }

    private void InitializeUinput()
    {
        try
        {
            _fd = open(UinputPath, O_WRONLY | O_NONBLOCK);
            if (_fd < 0)
            {
                int errno = Marshal.GetLastWin32Error();
                _logger.Warning($"LinuxUinputInjector: Unable to open {UinputPath} (errno={errno}). Input injection will be simulated or fallback.");
                return;
            }

            // Enable event types
            ioctl(_fd, UI_SET_EVBIT, EV_SYN);
            ioctl(_fd, UI_SET_EVBIT, EV_KEY);
            ioctl(_fd, UI_SET_EVBIT, EV_REL);

            // Enable relative mouse movement and scroll
            ioctl(_fd, UI_SET_RELBIT, REL_X);
            ioctl(_fd, UI_SET_RELBIT, REL_Y);
            ioctl(_fd, UI_SET_RELBIT, REL_WHEEL);
            ioctl(_fd, UI_SET_RELBIT, REL_HWHEEL);

            // Enable mouse buttons
            ioctl(_fd, UI_SET_KEYBIT, BTN_LEFT);
            ioctl(_fd, UI_SET_KEYBIT, BTN_RIGHT);
            ioctl(_fd, UI_SET_KEYBIT, BTN_MIDDLE);

            // Enable all standard keyboard keys (1 to 255)
            for (int k = 1; k < 255; k++)
            {
                ioctl(_fd, UI_SET_KEYBIT, k);
            }

            var setup = new UinputSetup
            {
                id = new InputId
                {
                    bustype = 0x03, // BUS_USB
                    vendor = 0x1234,
                    product = 0x5678,
                    version = 1
                },
                name = "Tether Virtual Input Device",
                ff_effects_max = 0
            };

            if (ioctl(_fd, UI_DEV_SETUP, ref setup) < 0)
            {
                int errno = Marshal.GetLastWin32Error();
                _logger.Warning($"LinuxUinputInjector: UI_DEV_SETUP failed (errno={errno}).");
                close(_fd);
                _fd = -1;
                return;
            }

            if (ioctl(_fd, UI_DEV_CREATE) < 0)
            {
                int errno = Marshal.GetLastWin32Error();
                _logger.Warning($"LinuxUinputInjector: UI_DEV_CREATE failed (errno={errno}).");
                close(_fd);
                _fd = -1;
                return;
            }

            _deviceCreated = true;
            _logger.Info("LinuxUinputInjector: Virtual uinput mouse and keyboard successfully created.");
        }
        catch (Exception ex)
        {
            _logger.Warning($"LinuxUinputInjector: Initialization exception: {ex.Message}");
            if (_fd >= 0)
            {
                close(_fd);
                _fd = -1;
            }
        }
    }

    public void Enqueue(byte[] frame)
    {
        if (_disposed || frame == null || frame.Length < 2) return;
        _inputQueue.Writer.TryWrite(frame);
    }

    public bool Handle(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 2) return false;
        if (frame[0] != PacketTypeInputEvent) return false;

        Enqueue(frame.ToArray());
        return true;
    }

    private void ProcessInputWorker()
    {
        var reader = _inputQueue.Reader;
        var token = _cts.Token;

        while (!token.IsCancellationRequested && !_disposed)
        {
            try
            {
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
                _logger.Error($"LinuxUinputInjector worker exception: {ex.Message}");
            }
        }

        ReleaseAllHeld();
    }

    public void DispatchFrame(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 2) return;
        if (frame[0] != PacketTypeInputEvent) return;

        byte subtype = frame[1];
        var payload = frame[2..];

        switch (subtype)
        {
            case SubtypeRelativeMove:
                if (payload.Length >= 4)
                {
                    short dx = BinaryPrimitives.ReadInt16BigEndian(payload[..2]);
                    short dy = BinaryPrimitives.ReadInt16BigEndian(payload[2..4]);
                    HandleRelativeMove(dx, dy);
                }
                break;

            case SubtypeButtonState:
                if (payload.Length >= 2)
                {
                    byte btn = payload[0];
                    byte state = payload[1];
                    HandleButtonState(btn, state);
                }
                break;

            case SubtypeScrollDelta:
                if (payload.Length >= 2)
                {
                    short scroll = BinaryPrimitives.ReadInt16BigEndian(payload[..2]);
                    HandleScroll(scroll);
                }
                break;

            case SubtypeVirtualKey:
                if (payload.Length >= 3)
                {
                    ushort vk = BinaryPrimitives.ReadUInt16BigEndian(payload[..2]);
                    byte flags = payload[2];
                    HandleVirtualKey(vk, flags);
                }
                break;

            case SubtypeUnicodeChar:
                if (payload.Length >= 2)
                {
                    ushort ch = BinaryPrimitives.ReadUInt16BigEndian(payload[..2]);
                    HandleUnicodeChar((char)ch);
                }
                break;

            case SubtypeAbsoluteMove:
                if (payload.Length >= 4)
                {
                    ushort nx = BinaryPrimitives.ReadUInt16BigEndian(payload[..2]);
                    ushort ny = BinaryPrimitives.ReadUInt16BigEndian(payload[2..4]);
                    HandleAbsoluteMove(nx, ny);
                }
                break;
        }
    }

    public void HandleRelativeMove(short dx, short dy)
    {
        if (dx != 0) EmitEvent(EV_REL, REL_X, dx);
        if (dy != 0) EmitEvent(EV_REL, REL_Y, dy);
        EmitSyn();
    }

    public void HandleAbsoluteMove(ushort nx, ushort ny)
    {
        // For relative pointer, absolute norm coordinates can be tracked or simulated
        EmitSyn();
    }

    public void HandleButtonState(byte buttonId, byte state)
    {
        ushort code = buttonId switch
        {
            MouseButtonLeft => BTN_LEFT,
            MouseButtonRight => BTN_RIGHT,
            MouseButtonMiddle => BTN_MIDDLE,
            _ => BTN_LEFT
        };

        bool isDown = state == ButtonStateDown;
        lock (_heldLock)
        {
            if (isDown) _heldButtons.Add(code);
            else _heldButtons.Remove(code);
        }

        EmitEvent(EV_KEY, code, isDown ? 1 : 0);
        EmitSyn();
    }

    public void HandleScroll(short scrollDelta)
    {
        if (scrollDelta == 0) return;
        // In Linux uinput REL_WHEEL, 1 is 1 notch up, -1 is 1 notch down
        int notches = scrollDelta / 120;
        if (notches == 0) notches = scrollDelta > 0 ? 1 : -1;

        EmitEvent(EV_REL, REL_WHEEL, notches);
        EmitSyn();
    }

    public void HandleVirtualKey(ushort vkCode, byte flags)
    {
        ushort key = MapVkToLinuxKey(vkCode);
        if (key == 0) return;

        bool isDown = flags == KeyStateDown;
        lock (_heldLock)
        {
            if (isDown) _heldKeys.Add(key);
            else _heldKeys.Remove(key);
        }

        EmitEvent(EV_KEY, key, isDown ? 1 : 0);
        EmitSyn();
    }

    public void HandleUnicodeChar(char ch)
    {
        var (key, shift) = MapCharToLinuxKey(ch);
        if (key == 0) return;

        if (shift)
        {
            EmitEvent(EV_KEY, 42, 1); // KEY_LEFTSHIFT down
            EmitSyn();
        }

        EmitEvent(EV_KEY, key, 1); // Key down
        EmitSyn();

        EmitEvent(EV_KEY, key, 0); // Key up
        EmitSyn();

        if (shift)
        {
            EmitEvent(EV_KEY, 42, 0); // KEY_LEFTSHIFT up
            EmitSyn();
        }
    }

    public void ReleaseAllHeld()
    {
        lock (_heldLock)
        {
            foreach (var btn in _heldButtons)
            {
                EmitEvent(EV_KEY, btn, 0);
            }
            _heldButtons.Clear();

            foreach (var key in _heldKeys)
            {
                EmitEvent(EV_KEY, key, 0);
            }
            _heldKeys.Clear();
        }
        EmitSyn();
    }

    private void EmitSyn()
    {
        EmitEvent(EV_SYN, SYN_REPORT, 0);
    }

    private void EmitEvent(ushort type, ushort code, int value)
    {
        OnEventInjected?.Invoke(type, code, value);

        if (!_deviceCreated || _fd < 0) return;

        var ev = new LinuxInputEvent
        {
            type = type,
            code = code,
            value = value
        };

        write(_fd, ref ev, (UIntPtr)Marshal.SizeOf<LinuxInputEvent>());
    }

    public static ushort MapVkToLinuxKey(ushort vk)
    {
        return vk switch
        {
            0x08 => 14, // KEY_BACKSPACE
            0x09 => 15, // KEY_TAB
            0x0D => 28, // KEY_ENTER
            0x10 => 42, // KEY_LEFTSHIFT
            0x11 => 29, // KEY_LEFTCTRL
            0x12 => 56, // KEY_LEFTALT
            0x13 => 119,// KEY_PAUSE
            0x14 => 58, // KEY_CAPSLOCK
            0x1B => 1,  // KEY_ESC
            0x20 => 57, // KEY_SPACE
            0x21 => 104,// KEY_PAGEUP
            0x22 => 109,// KEY_PAGEDOWN
            0x23 => 107,// KEY_END
            0x24 => 102,// KEY_HOME
            0x25 => 105,// KEY_LEFT
            0x26 => 103,// KEY_UP
            0x27 => 106,// KEY_RIGHT
            0x28 => 108,// KEY_DOWN
            0x2D => 110,// KEY_INSERT
            0x2E => 111,// KEY_DELETE
            0x5B => 125,// KEY_LEFTMETA
            0x5C => 126,// KEY_RIGHTMETA

            // Numbers '0'..'9'
            0x30 => 11, // KEY_0
            0x31 => 2,  // KEY_1
            0x32 => 3,  // KEY_2
            0x33 => 4,  // KEY_3
            0x34 => 5,  // KEY_4
            0x35 => 6,  // KEY_5
            0x36 => 7,  // KEY_6
            0x37 => 8,  // KEY_7
            0x38 => 9,  // KEY_8
            0x39 => 10, // KEY_9

            // Letters 'A'..'Z'
            0x41 => 30, // KEY_A
            0x42 => 48, // KEY_B
            0x43 => 46, // KEY_C
            0x44 => 32, // KEY_D
            0x45 => 18, // KEY_E
            0x46 => 33, // KEY_F
            0x47 => 34, // KEY_G
            0x48 => 35, // KEY_H
            0x49 => 23, // KEY_I
            0x4A => 36, // KEY_J
            0x4B => 37, // KEY_K
            0x4C => 38, // KEY_L
            0x4D => 50, // KEY_M
            0x4E => 49, // KEY_N
            0x4F => 24, // KEY_O
            0x50 => 25, // KEY_P
            0x51 => 16, // KEY_Q
            0x52 => 19, // KEY_R
            0x53 => 31, // KEY_S
            0x54 => 20, // KEY_T
            0x55 => 22, // KEY_U
            0x56 => 47, // KEY_V
            0x57 => 17, // KEY_W
            0x58 => 45, // KEY_X
            0x59 => 21, // KEY_Y
            0x5A => 44, // KEY_Z

            // F1..F12
            0x70 => 59, // KEY_F1
            0x71 => 60, // KEY_F2
            0x72 => 61, // KEY_F3
            0x73 => 62, // KEY_F4
            0x74 => 63, // KEY_F5
            0x75 => 64, // KEY_F6
            0x76 => 65, // KEY_F7
            0x77 => 66, // KEY_F8
            0x78 => 67, // KEY_F9
            0x79 => 68, // KEY_F10
            0x7A => 87, // KEY_F11
            0x7B => 88, // KEY_F12

            _ => 0
        };
    }

    public static (ushort key, bool shift) MapCharToLinuxKey(char c)
    {
        if (c >= 'a' && c <= 'z') return (MapVkToLinuxKey((ushort)(0x41 + (c - 'a'))), false);
        if (c >= 'A' && c <= 'Z') return (MapVkToLinuxKey((ushort)(0x41 + (c - 'A'))), true);
        if (c >= '0' && c <= '9') return (MapVkToLinuxKey((ushort)(0x30 + (c - '0'))), false);

        return c switch
        {
            ' ' => (57, false), // KEY_SPACE
            '\n' or '\r' => (28, false), // KEY_ENTER
            '\t' => (15, false), // KEY_TAB
            '\b' => (14, false), // KEY_BACKSPACE
            '!' => (2, true),    // Shift + 1
            '@' => (3, true),    // Shift + 2
            '#' => (4, true),    // Shift + 3
            '$' => (5, true),    // Shift + 4
            '%' => (6, true),    // Shift + 5
            '^' => (7, true),    // Shift + 6
            '&' => (8, true),    // Shift + 7
            '*' => (9, true),    // Shift + 8
            '(' => (10, true),   // Shift + 9
            ')' => (11, true),   // Shift + 0
            '-' => (12, false),  // KEY_MINUS
            '_' => (12, true),   // Shift + KEY_MINUS
            '=' => (13, false),  // KEY_EQUAL
            '+' => (13, true),   // Shift + KEY_EQUAL
            '[' => (26, false),  // KEY_LEFTBRACE
            '{' => (26, true),
            ']' => (27, false),  // KEY_RIGHTBRACE
            '}' => (27, true),
            ';' => (39, false),  // KEY_SEMICOLON
            ':' => (39, true),
            '\'' => (40, false), // KEY_APOSTROPHE
            '"' => (40, true),
            '`' => (41, false),  // KEY_GRAVE
            '~' => (41, true),
            '\\' => (43, false), // KEY_BACKSLASH
            '|' => (43, true),
            ',' => (51, false),  // KEY_COMMA
            '<' => (51, true),
            '.' => (52, false),  // KEY_DOT
            '>' => (52, true),
            '/' => (53, false),  // KEY_SLASH
            '?' => (53, true),
            _ => (0, false)
        };
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _cts.Cancel();
        _inputQueue.Writer.TryComplete();

        try { _workerThread.Join(500); } catch { }

        ReleaseAllHeld();

        if (_deviceCreated && _fd >= 0)
        {
            ioctl(_fd, UI_DEV_DESTROY);
            _deviceCreated = false;
        }

        if (_fd >= 0)
        {
            close(_fd);
            _fd = -1;
        }

        _cts.Dispose();
    }
}
