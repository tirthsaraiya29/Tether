using System;
using System.Runtime.InteropServices;
using Tether.SessionHelper;
using Xunit;

namespace Tether.Tests;

public class Win32InputAbiTests
{
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
