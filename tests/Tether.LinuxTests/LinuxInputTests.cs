using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Threading;
using Tether.LinuxDaemon.Input;
using Tether.Shared.Logging;
using Xunit;

namespace Tether.LinuxTests;

public class LinuxInputTests
{
    private readonly ITetherLogger _logger = new SerilogTetherLogger();

    [Fact]
    public void TestVkToLinuxKeyMapping()
    {
        Assert.Equal(14, LinuxUinputInjector.MapVkToLinuxKey(0x08)); // Backspace
        Assert.Equal(28, LinuxUinputInjector.MapVkToLinuxKey(0x0D)); // Enter
        Assert.Equal(1, LinuxUinputInjector.MapVkToLinuxKey(0x1B));  // Esc
        Assert.Equal(57, LinuxUinputInjector.MapVkToLinuxKey(0x20)); // Space
        Assert.Equal(30, LinuxUinputInjector.MapVkToLinuxKey(0x41)); // 'A'
        Assert.Equal(11, LinuxUinputInjector.MapVkToLinuxKey(0x30)); // '0'
        Assert.Equal(59, LinuxUinputInjector.MapVkToLinuxKey(0x70)); // F1
    }

    [Fact]
    public void TestCharToLinuxKeyMapping()
    {
        var (kLower, sLower) = LinuxUinputInjector.MapCharToLinuxKey('a');
        Assert.Equal(30, kLower);
        Assert.False(sLower);

        var (kUpper, sUpper) = LinuxUinputInjector.MapCharToLinuxKey('A');
        Assert.Equal(30, kUpper);
        Assert.True(sUpper);

        var (kExcl, sExcl) = LinuxUinputInjector.MapCharToLinuxKey('!');
        Assert.Equal(2, kExcl);
        Assert.True(sExcl);

        var (kSpace, sSpace) = LinuxUinputInjector.MapCharToLinuxKey(' ');
        Assert.Equal(57, kSpace);
        Assert.False(sSpace);
    }

    [Fact]
    public void TestRelativeMoveDispatched()
    {
        using var injector = new LinuxUinputInjector(_logger);
        var events = new List<(ushort type, ushort code, int val)>();
        injector.OnEventInjected = (t, c, v) => events.Add((t, c, v));

        // SubtypeRelativeMove: dx=10, dy=-5
        byte[] frame = new byte[6];
        frame[0] = LinuxUinputInjector.PacketTypeInputEvent;
        frame[1] = LinuxUinputInjector.SubtypeRelativeMove;
        BinaryPrimitives.WriteInt16BigEndian(frame.AsSpan(2, 2), 10);
        BinaryPrimitives.WriteInt16BigEndian(frame.AsSpan(4, 2), -5);

        injector.DispatchFrame(frame);

        // Should emit EV_REL X (0), EV_REL Y (1), EV_SYN (0)
        Assert.Contains(events, e => e.type == 2 && e.code == 0 && e.val == 10);
        Assert.Contains(events, e => e.type == 2 && e.code == 1 && e.val == -5);
        Assert.Contains(events, e => e.type == 0 && e.code == 0 && e.val == 0);
    }

    [Fact]
    public void TestButtonStateAndReleaseAllHeld()
    {
        using var injector = new LinuxUinputInjector(_logger);
        var events = new List<(ushort type, ushort code, int val)>();
        injector.OnEventInjected = (t, c, v) => events.Add((t, c, v));

        // SubtypeButtonState: Left click down
        byte[] frame = new byte[]
        {
            LinuxUinputInjector.PacketTypeInputEvent,
            LinuxUinputInjector.SubtypeButtonState,
            LinuxUinputInjector.MouseButtonLeft,
            LinuxUinputInjector.ButtonStateDown
        };

        injector.DispatchFrame(frame);

        // BTN_LEFT is 0x110 (272)
        Assert.Contains(events, e => e.type == 1 && e.code == 272 && e.val == 1);

        events.Clear();
        // Now release all held
        injector.ReleaseAllHeld();

        // Must emit BTN_LEFT up
        Assert.Contains(events, e => e.type == 1 && e.code == 272 && e.val == 0);
    }

    [Fact]
    public void TestScrollDelta()
    {
        using var injector = new LinuxUinputInjector(_logger);
        var events = new List<(ushort type, ushort code, int val)>();
        injector.OnEventInjected = (t, c, v) => events.Add((t, c, v));

        byte[] frame = new byte[4];
        frame[0] = LinuxUinputInjector.PacketTypeInputEvent;
        frame[1] = LinuxUinputInjector.SubtypeScrollDelta;
        BinaryPrimitives.WriteInt16BigEndian(frame.AsSpan(2, 2), 120); // 1 notch up

        injector.DispatchFrame(frame);

        // REL_WHEEL = 8
        Assert.Contains(events, e => e.type == 2 && e.code == 8 && e.val == 1);
    }

    [Fact]
    public void TestVirtualKeyAndUnicodeChar()
    {
        using var injector = new LinuxUinputInjector(_logger);
        var events = new List<(ushort type, ushort code, int val)>();
        injector.OnEventInjected = (t, c, v) => events.Add((t, c, v));

        // Virtual key: VK_RETURN (0x0D), KeyStateDown (1)
        byte[] vkFrame = new byte[5];
        vkFrame[0] = LinuxUinputInjector.PacketTypeInputEvent;
        vkFrame[1] = LinuxUinputInjector.SubtypeVirtualKey;
        BinaryPrimitives.WriteUInt16BigEndian(vkFrame.AsSpan(2, 2), 0x0D);
        vkFrame[4] = LinuxUinputInjector.KeyStateDown;

        injector.DispatchFrame(vkFrame);
        Assert.Contains(events, e => e.type == 1 && e.code == 28 && e.val == 1); // KEY_ENTER

        events.Clear();

        // Unicode char: '!' (maps to shift + 1)
        byte[] uniFrame = new byte[4];
        uniFrame[0] = LinuxUinputInjector.PacketTypeInputEvent;
        uniFrame[1] = LinuxUinputInjector.SubtypeUnicodeChar;
        BinaryPrimitives.WriteUInt16BigEndian(uniFrame.AsSpan(2, 2), (ushort)'!');

        injector.DispatchFrame(uniFrame);
        Assert.Contains(events, e => e.type == 1 && e.code == 42 && e.val == 1); // KEY_LEFTSHIFT down
        Assert.Contains(events, e => e.type == 1 && e.code == 2 && e.val == 1);  // KEY_1 down
        Assert.Contains(events, e => e.type == 1 && e.code == 2 && e.val == 0);  // KEY_1 up
        Assert.Contains(events, e => e.type == 1 && e.code == 42 && e.val == 0); // KEY_LEFTSHIFT up
    }

    [Fact]
    public void TestAsyncEnqueueWorker()
    {
        using var injector = new LinuxUinputInjector(_logger);
        var events = new List<(ushort type, ushort code, int val)>();
        injector.OnEventInjected = (t, c, v) => { lock (events) events.Add((t, c, v)); };

        byte[] frame = new byte[6];
        frame[0] = LinuxUinputInjector.PacketTypeInputEvent;
        frame[1] = LinuxUinputInjector.SubtypeRelativeMove;
        BinaryPrimitives.WriteInt16BigEndian(frame.AsSpan(2, 2), 25);
        BinaryPrimitives.WriteInt16BigEndian(frame.AsSpan(4, 2), 30);

        bool handled = injector.Handle(frame);
        Assert.True(handled);

        // Wait for worker thread to process
        int attempts = 0;
        while (attempts < 50)
        {
            lock (events)
            {
                if (events.Count >= 3) break;
            }
            Thread.Sleep(10);
            attempts++;
        }

        lock (events)
        {
            Assert.Contains(events, e => e.type == 2 && e.code == 0 && e.val == 25);
            Assert.Contains(events, e => e.type == 2 && e.code == 1 && e.val == 30);
        }
    }
}
