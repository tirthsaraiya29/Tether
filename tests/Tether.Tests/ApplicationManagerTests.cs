using System;
using Tether.SessionHelper;
using Xunit;

namespace Tether.Tests;

public class ApplicationManagerTests
{
    [Fact]
    public void GetRunningWindows_ReturnsOnlyRealTitledWindows()
    {
        var windows = ApplicationManager.GetRunningWindows();

        Assert.NotNull(windows);
        Assert.DoesNotContain(windows, w => w.Title == "Program Manager");
        Assert.All(windows, w =>
        {
            Assert.False(string.IsNullOrWhiteSpace(w.Title));
            Assert.True(w.Hwnd != 0);
        });
    }

    [Fact]
    public void GetRunningWindows_IsDistinctFromInstalledApplications()
    {
        // Window enumeration must not degrade into a process dump: every entry needs a window handle.
        var windows = ApplicationManager.GetRunningWindows();
        Assert.All(windows, w => Assert.True(w.Hwnd > 0));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void LaunchApplication_RejectsNullOrWhitespace(string? input)
    {
        bool result = ApplicationManager.LaunchApplication(input!);
        Assert.False(result);
    }

    [Theory]
    [InlineData("calc.exe & notepad.exe")]
    [InlineData("calc.exe | notepad.exe")]
    [InlineData("calc.exe > output.txt")]
    [InlineData("calc.exe < input.txt")]
    [InlineData("calc.exe ^& notepad.exe")]
    [InlineData("calc.exe; notepad.exe")]
    [InlineData("calc.exe` notepad.exe")]
    public void LaunchApplication_RejectsCommandChainingInPath(string maliciousPath)
    {
        bool result = ApplicationManager.LaunchApplication(maliciousPath);
        Assert.False(result);
    }

    [Theory]
    [InlineData("& echo pwned")]
    [InlineData("| whoami")]
    [InlineData("; calc.exe")]
    [InlineData("> out.txt")]
    public void LaunchApplication_RejectsCommandChainingInArguments(string maliciousArgs)
    {
        bool result = ApplicationManager.LaunchApplication("notepad.exe", maliciousArgs);
        Assert.False(result);
    }

    [Theory]
    [InlineData("calc.exe\nnotepad.exe")]
    [InlineData("calc.exe\r\nnotepad.exe")]
    [InlineData("calc.exe\0")]
    public void LaunchApplication_RejectsControlCharacters(string maliciousPath)
    {
        bool result = ApplicationManager.LaunchApplication(maliciousPath);
        Assert.False(result);
    }

    [Theory]
    [InlineData("cmd.exe")]
    [InlineData("CMD.EXE")]
    [InlineData("cmd")]
    [InlineData(@"C:\Windows\System32\cmd.exe")]
    [InlineData("powershell.exe")]
    [InlineData("powershell")]
    [InlineData("pwsh.exe")]
    [InlineData("mshta.exe")]
    [InlineData("cscript.exe")]
    [InlineData("wscript.exe")]
    [InlineData("bash.exe")]
    [InlineData("wsl.exe")]
    public void LaunchApplication_BlocksShellInterpreters(string shellPath)
    {
        bool result = ApplicationManager.LaunchApplication(shellPath);
        Assert.False(result);
    }

    [Theory]
    [InlineData("malicious.bat")]
    [InlineData("payload.cmd")]
    [InlineData("script.ps1")]
    [InlineData("script.psm1")]
    [InlineData("payload.vbs")]
    [InlineData("app.hta")]
    [InlineData("regfix.reg")]
    public void LaunchApplication_BlocksScriptExtensions(string scriptPath)
    {
        bool result = ApplicationManager.LaunchApplication(scriptPath);
        Assert.False(result);
    }
}
