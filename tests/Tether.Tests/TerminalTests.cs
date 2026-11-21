using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Tether.SessionHelper;
using Xunit;

namespace Tether.Tests;

public class TerminalTests
{
    [Fact]
    public async Task StartSession_PowerShell_LaunchesSuccessfully_AndAcceptsInput()
    {
        var output = new StringBuilder();
        var outputReceived = new AutoResetEvent(false);

        var mgr = new TerminalSessionManager((sessionId, data, workingDir, ownerDeviceId) =>
        {
            output.Append(data);
            outputReceived.Set();
        });

        var session = mgr.StartSession("powershell", null, null, "test-device-id");
        Assert.NotNull(session);
        Assert.NotEmpty(session.Id);

        // Wait for initial output
        Assert.True(outputReceived.WaitOne(TimeSpan.FromSeconds(5)));

        // Send a simple command: Write-Output "TETHER_TEST_OK"
        bool sent = mgr.SendInput(session.Id, "Write-Output 'TETHER_TEST_OK'\r\n", "test-device-id");
        Assert.True(sent);

        // Wait up to 5s for command output
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (DateTime.UtcNow < deadline && !output.ToString().Contains("TETHER_TEST_OK"))
        {
            await Task.Delay(100);
        }

        Assert.Contains("TETHER_TEST_OK", output.ToString());

        mgr.CloseSession(session.Id, "test-device-id");
    }

    [Fact]
    public void SendInput_RestrictedAdminCommand_IsBlockedBySecurityPolicy()
    {
        var output = new StringBuilder();
        var mgr = new TerminalSessionManager((sessionId, data, workingDir, ownerDeviceId) =>
        {
            output.Append(data);
        });

        var session = mgr.StartSession("powershell", null, null, "test-device-id");
        Assert.NotNull(session);

        // Test restricted administrative elevation pattern
        bool sent = mgr.SendInput(session.Id, "sudo whoami\r\n", "test-device-id");
        Assert.False(sent);
        Assert.Contains("Command blocked: administrative elevation", output.ToString());

        mgr.CloseSession(session.Id, "test-device-id");
    }

    [Fact]
    public void TerminalSession_CrossDeviceAccess_IsDenied()
    {
        var mgr = new TerminalSessionManager((_, _, _, _) => { });
        var session = mgr.StartSession("powershell", null, null, "device-owner");

        // Attacker device tries to send input
        bool sent = mgr.SendInput(session.Id, "whoami\r\n", "attacker-device");
        Assert.False(sent);

        // Attacker device tries to close session
        bool closed = mgr.CloseSession(session.Id, "attacker-device");
        Assert.False(closed);

        // Legitimate device closes session
        bool legitClose = mgr.CloseSession(session.Id, "device-owner");
        Assert.True(legitClose);
    }
}
