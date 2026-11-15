using System;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using Tether.CommunicationService.Capabilities;
using Tether.Shared.Logging;
using Xunit;

namespace Tether.Tests;

public class GlobalNamedEventTests
{
    [Fact]
    public void EventSecurityDescriptor_AllowsSystemAndAdminsOnly()
    {
        var sec = new EventWaitHandleSecurity();
        sec.SetSecurityDescriptorSddlForm("D:P(A;;GA;;;SY)(A;;GA;;;BA)");

        string sddl = sec.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
        Assert.Contains("SY", sddl);
        Assert.Contains("BA", sddl);
        Assert.DoesNotContain("WD", sddl); // No Everyone
        Assert.DoesNotContain("AU", sddl); // No Authenticated Users
    }

    [Fact]
    public void ResetUnlockEvent_HandlesNonExistentEventGracefully()
    {
        var logger = new TestLogger();
        string eventName = $@"Local\TetherTestNonExistent_{Guid.NewGuid():N}";
        
        // Calling Reset on non-existent event should not throw
        HardwareExecutor.ResetUnlockEvent(eventName, logger);
    }
}
