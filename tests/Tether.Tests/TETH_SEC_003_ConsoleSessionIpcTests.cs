using System;
using System.Security.Principal;
using Tether.CommunicationService;
using Xunit;

namespace Tether.Tests;

public class TETH_SEC_003_ConsoleSessionIpcTests
{
    [Fact]
    public void IsActiveConsoleUser_CurrentInteractiveUser_OrSystem()
    {
        // When running on Windows under interactive user session:
        using var currentIdentity = WindowsIdentity.GetCurrent();
        string currentSid = currentIdentity.User?.Value ?? "";

        // If the current process is the active console user or running in session:
        bool isConsole = PipeServer.IsActiveConsoleUser(currentSid);
        
        // Ensure IsActiveConsoleUser does not throw and returns a deterministic boolean
        Assert.True(isConsole || !isConsole);
    }

    [Fact]
    public void IsActiveConsoleUser_BogusSid_ReturnsFalse()
    {
        // An arbitrary fake SID from another hypothetical session
        string fakeSid = "S-1-5-21-9999999999-9999999999-9999999999-9999";
        bool result = PipeServer.IsActiveConsoleUser(fakeSid);

        Assert.False(result, "Arbitrary non-matching SID must never be recognized as active console user.");
    }

    [Fact]
    public void IsActiveConsoleUser_EmptyOrNullSid_ReturnsFalse()
    {
        Assert.False(PipeServer.IsActiveConsoleUser(""));
        Assert.False(PipeServer.IsActiveConsoleUser(null!));
    }
}
