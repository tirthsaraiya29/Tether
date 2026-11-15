using System;
using System.Runtime.InteropServices;
using Tether.SessionHelper;
using Xunit;

namespace Tether.Tests;

public class Win32InputAbiTests
{
    [Fact]
    public void ClipboardController_InputStructSize_MatchesWin32Abi()
    {
        if (Environment.Is64BitProcess)
        {
            // On x64 Windows:
            // uint type (4 bytes) + 4 bytes padding + union (32 bytes) = 40 bytes.
            int size = Marshal.SizeOf<ClipboardController.INPUT>();
            Assert.Equal(40, size);
        }
    }

    [Fact]
    public void InputInjector_InputStructSize_MatchesWin32Abi()
    {
        if (Environment.Is64BitProcess)
        {
            int size = Marshal.SizeOf<InputInjector.INPUT>();
            Assert.Equal(40, size);
        }
    }
}
