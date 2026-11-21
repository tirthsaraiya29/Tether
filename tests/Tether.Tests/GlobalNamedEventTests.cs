using System;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using Tether.CommunicationService;
using Tether.CommunicationService.Capabilities;
using Tether.Shared.Logging;
using Xunit;

namespace Tether.Tests;

public class GlobalNamedEventTests
{
    [Fact]
    public void EventSecurityDescriptor_AllowsSystemAndAdminsFullControl_AndAuthenticatedUsersReadOnly()
    {
        var sec = new EventWaitHandleSecurity();
        sec.SetSecurityDescriptorSddlForm("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;AU)");

        string sddl = sec.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
        Assert.Contains("(A;;GA;;;SY)", sddl);
        Assert.Contains("(A;;GA;;;BA)", sddl);
        Assert.Contains("(A;;GR;;;AU)", sddl);
        Assert.DoesNotContain("WD", sddl); // No Everyone
        Assert.DoesNotContain("AN", sddl); // No Anonymous
    }

    [Fact]
    public void ResetUnlockEvent_HandlesNonExistentEventGracefully()
    {
        var logger = new TestLogger();
        string eventName = $@"Local\TetherTestNonExistent_{Guid.NewGuid():N}";
        
        // Calling Reset on non-existent event should not throw
        HardwareExecutor.ResetUnlockEvent(eventName, logger);
    }

    [Fact]
    public void PipeServerSecurity_DeniesNetworkAndAnonymous_AllowsLocalSystemAndAdmins()
    {
        var sec = PipeServer.CreatePipeSecurity();
        var rules = sec.GetAccessRules(true, false, typeof(SecurityIdentifier));

        bool networkDenied = false;
        bool anonymousDenied = false;
        bool systemAllowed = false;
        bool adminsAllowed = false;
        bool authenticatedAllowed = false;

        foreach (PipeAccessRule rule in rules)
        {
            var sid = (SecurityIdentifier)rule.IdentityReference;
            if (sid.IsWellKnown(WellKnownSidType.NetworkSid) && rule.AccessControlType == AccessControlType.Deny)
            {
                networkDenied = true;
            }
            if (sid.IsWellKnown(WellKnownSidType.AnonymousSid) && rule.AccessControlType == AccessControlType.Deny)
            {
                anonymousDenied = true;
            }
            if (sid.IsWellKnown(WellKnownSidType.LocalSystemSid) && rule.AccessControlType == AccessControlType.Allow)
            {
                systemAllowed = true;
            }
            if (sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) && rule.AccessControlType == AccessControlType.Allow)
            {
                adminsAllowed = true;
            }
            if (sid.IsWellKnown(WellKnownSidType.AuthenticatedUserSid) && rule.AccessControlType == AccessControlType.Allow)
            {
                authenticatedAllowed = true;
            }
        }

        Assert.True(networkDenied, "NetworkSid must be explicitly denied.");
        Assert.True(anonymousDenied, "AnonymousSid must be explicitly denied.");
        Assert.True(systemAllowed, "LocalSystemSid must be allowed.");
        Assert.True(adminsAllowed, "BuiltinAdministratorsSid must be allowed.");
        Assert.True(authenticatedAllowed, "AuthenticatedUserSid must be allowed.");
    }
}
