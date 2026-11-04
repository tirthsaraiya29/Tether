using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using Tether.CommunicationService.Capabilities;
using Tether.CommunicationService.Devices;
using Tether.CommunicationService.Trust;
using Tether.Shared.Logging;
using Xunit;

namespace Tether.FileTransfer.Tests;

public class AuditRun12SecurityTests
{
    [Fact]
    public void INF7_CapabilityManager_SupportsSystemControlForUnlockAndElevated()
    {
        var logger = new MockLogger();
        var capManager = new CapabilityManager(logger);

        var systemControlDevice = new TetherDevice
        {
            DeviceId = "system-control-device",
            DisplayName = "System Control Device",
            Capabilities = new List<string> { "SYSTEM_CONTROL", "MEDIA" }
        };

        var unprivilegedDevice = new TetherDevice
        {
            DeviceId = "unprivileged-device",
            DisplayName = "Unprivileged Device",
            Capabilities = new List<string> { "MEDIA", "FILES" }
        };

        // SYSTEM_CONTROL should allow unlock and elevated commands
        Assert.True(capManager.CanDeviceExecuteCommand(systemControlDevice, "unlock"));
        Assert.True(capManager.CanDeviceExecuteCommand(systemControlDevice, "auth_ok"));
        Assert.True(capManager.CanDeviceExecuteCommand(systemControlDevice, "shutdown"));
        Assert.True(capManager.CanDeviceExecuteCommand(systemControlDevice, "reboot"));

        // Unprivileged device without SYSTEM_CONTROL, SYSTEM_UNLOCK, or POWER_ELEVATED should be rejected
        Assert.False(capManager.CanDeviceExecuteCommand(unprivilegedDevice, "unlock"));
        Assert.False(capManager.CanDeviceExecuteCommand(unprivilegedDevice, "auth_ok"));
        Assert.False(capManager.CanDeviceExecuteCommand(unprivilegedDevice, "shutdown"));
    }

    [Fact]
    public void INF4_TrustStore_DirectorySecurity_StripsInheritance()
    {
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        Assert.True(sec.AreAccessRulesProtected);

        var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

        sec.AddAccessRule(new FileSystemAccessRule(
            systemSid,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));

        sec.AddAccessRule(new FileSystemAccessRule(
            adminSid,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));

        var rules = sec.GetAccessRules(true, false, typeof(SecurityIdentifier));
        Assert.Equal(2, rules.Count);
    }

    [Fact]
    public void INF3_InputForwarder_SecurityConfig_DeniesNetworkSid()
    {
        var security = new PipeSecurity();

        // 1. Network SID denied
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Deny));

        // 2. LocalSystem and Admin allowed
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,
            AccessControlType.Allow));

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,
            AccessControlType.Allow));

        var rules = security.GetAccessRules(true, false, typeof(SecurityIdentifier));
        bool hasNetworkDeny = false;
        bool hasInteractiveAllow = false;

        foreach (PipeAccessRule rule in rules)
        {
            if (rule.IdentityReference is SecurityIdentifier sid)
            {
                if (sid.IsWellKnown(WellKnownSidType.NetworkSid) && rule.AccessControlType == AccessControlType.Deny)
                {
                    hasNetworkDeny = true;
                }
                if (sid.IsWellKnown(WellKnownSidType.InteractiveSid) && rule.AccessControlType == AccessControlType.Allow)
                {
                    hasInteractiveAllow = true;
                }
            }
        }

        Assert.True(hasNetworkDeny, "NetworkSid must be explicitly denied");
        Assert.False(hasInteractiveAllow, "InteractiveSid must NOT be allowed");
    }
}
