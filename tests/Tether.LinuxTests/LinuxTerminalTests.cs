using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Tether.LinuxDaemon.Terminal;
using Tether.Shared.Logging;
using Xunit;

namespace Tether.LinuxTests;

public class LinuxTerminalTests : IDisposable
{
    private readonly ITetherLogger _logger = new SerilogTetherLogger();
    private readonly LinuxTerminalManager _manager;

    public LinuxTerminalTests()
    {
        _manager = new LinuxTerminalManager(_logger);
    }

    public void Dispose()
    {
        _manager.Dispose();
    }

    [Fact]
    public async Task StartSession_AndExecuteCommand_ProducesOutput()
    {
        var outputChunks = new List<string>();
        var tcs = new TaskCompletionSource<string>();

        _manager.OnOutputReceived = (sessId, text, dir, owner) =>
        {
            lock (outputChunks)
            {
                outputChunks.Add(text);
                if (text.Contains("TETHER_LINUX_ECHO_TEST"))
                {
                    tcs.TrySetResult(text);
                }
            }
        };

        var session = _manager.StartSession("bash", ownerDeviceId: "test-device-1");
        Assert.NotNull(session);
        Assert.NotEmpty(session.Id);
        Assert.Equal("test-device-1", session.OwnerDeviceId);

        // Send echo command
        bool sent = _manager.SendInput(session.Id, "echo TETHER_LINUX_ECHO_TEST\n", ownerDeviceId: "test-device-1");
        Assert.True(sent);

        // Await echo response up to 3 seconds
        var completed = await Task.WhenAny(tcs.Task, Task.Delay(3000));
        Assert.Same(tcs.Task, completed);
        string result = await tcs.Task;
        Assert.Contains("TETHER_LINUX_ECHO_TEST", result);

        // Close session
        bool closed = _manager.CloseSession(session.Id, ownerDeviceId: "test-device-1");
        Assert.True(closed);
    }

    [Fact]
    public void BlockRestrictedElevationCommands()
    {
        var alerts = new List<string>();
        _manager.OnOutputReceived = (sessId, text, dir, owner) =>
        {
            if (text.Contains("[Security Notice]"))
            {
                lock (alerts) alerts.Add(text);
            }
        };

        var session = _manager.StartSession("sh", ownerDeviceId: "test-device-sec");

        // Try sudo
        bool sudoResult = _manager.SendInput(session.Id, "sudo cat /etc/shadow\n", ownerDeviceId: "test-device-sec");
        Assert.False(sudoResult);

        // Try su
        bool suResult = _manager.SendInput(session.Id, "su - root\n", ownerDeviceId: "test-device-sec");
        Assert.False(suResult);

        // Try pkexec
        bool pkResult = _manager.SendInput(session.Id, "pkexec bash\n", ownerDeviceId: "test-device-sec");
        Assert.False(pkResult);

        lock (alerts)
        {
            Assert.NotEmpty(alerts);
            Assert.Contains(alerts, a => a.Contains("administrative elevation"));
        }
    }

    [Fact]
    public void RejectCrossDeviceAccess()
    {
        var session = _manager.StartSession("sh", ownerDeviceId: "device-owner-A");

        // Device B cannot send input
        bool bInput = _manager.SendInput(session.Id, "echo hello\n", ownerDeviceId: "device-intruder-B");
        Assert.False(bInput);

        // Device B cannot close session
        bool bClose = _manager.CloseSession(session.Id, ownerDeviceId: "device-intruder-B");
        Assert.False(bClose);

        // Device B cannot get history
        var bHistory = _manager.GetHistory(session.Id, ownerDeviceId: "device-intruder-B");
        Assert.Empty(bHistory);

        // Device A can close session
        bool aClose = _manager.CloseSession(session.Id, ownerDeviceId: "device-owner-A");
        Assert.True(aClose);
    }

    [Fact]
    public void ListSessions_FiltersByOwner()
    {
        var s1 = _manager.StartSession("sh", ownerDeviceId: "dev-alpha");
        var s2 = _manager.StartSession("sh", ownerDeviceId: "dev-beta");

        var alphaSessions = _manager.ListSessions("dev-alpha");
        Assert.Single(alphaSessions);
        Assert.Equal(s1.Id, alphaSessions[0].Id);

        var betaSessions = _manager.ListSessions("dev-beta");
        Assert.Single(betaSessions);
        Assert.Equal(s2.Id, betaSessions[0].Id);
    }

    [Fact]
    public async Task SendInput_NormalizesCarriageReturns_ForLinuxShell()
    {
        var outputChunks = new List<string>();
        var tcs = new TaskCompletionSource<string>();

        _manager.OnOutputReceived = (sessId, text, dir, owner) =>
        {
            lock (outputChunks)
            {
                outputChunks.Add(text);
                if (text.Contains("CR_NORMALIZED_TEST"))
                {
                    tcs.TrySetResult(text);
                }
            }
        };

        var session = _manager.StartSession("bash", ownerDeviceId: "test-device-cr");
        Assert.NotNull(session);

        // Send input with Windows-style CRLF (\r\n)
        bool sent = _manager.SendInput(session.Id, "echo CR_NORMALIZED_TEST\r\n", ownerDeviceId: "test-device-cr");
        Assert.True(sent);

        var completed = await Task.WhenAny(tcs.Task, Task.Delay(3000));
        Assert.Same(tcs.Task, completed);
        string result = await tcs.Task;
        Assert.Contains("CR_NORMALIZED_TEST", result);

        _manager.CloseSession(session.Id, ownerDeviceId: "test-device-cr");
    }

    [Fact]
    public void SendInput_RejectsOversizedInput()
    {
        var session = _manager.StartSession("sh", ownerDeviceId: "test-device-oversize");
        string oversized = new string('A', 35000);
        bool sent = _manager.SendInput(session.Id, oversized, ownerDeviceId: "test-device-oversize");
        Assert.False(sent);
        _manager.CloseSession(session.Id, ownerDeviceId: "test-device-oversize");
    }

    [Fact]
    public void SendInput_CtrlC_HandlesSigintWithoutCrashing()
    {
        var session = _manager.StartSession("sh", ownerDeviceId: "test-device-ctrlc");
        bool sent = _manager.SendInput(session.Id, "\x03", ownerDeviceId: "test-device-ctrlc");
        Assert.True(sent);
        _manager.CloseSession(session.Id, ownerDeviceId: "test-device-ctrlc");
    }
}
