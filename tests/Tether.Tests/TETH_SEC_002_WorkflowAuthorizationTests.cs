using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Tether.CommunicationService.Automation;
using Tether.CommunicationService.Capabilities;
using Tether.CommunicationService.Trust;
using Tether.Shared.Logging;
using Xunit;

namespace Tether.Tests;

public class TETH_SEC_002_WorkflowAuthorizationTests
{
    private readonly string _testDir;

    public TETH_SEC_002_WorkflowAuthorizationTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "Tether_Test_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testDir);
    }

    [Theory]
    [InlineData("unlock", "POWER_ELEVATED")]
    [InlineData("shutdown", "POWER_ELEVATED")]
    [InlineData("reboot", "POWER_ELEVATED")]
    [InlineData("sleep", "POWER_ELEVATED")]
    [InlineData("auth_ok", "POWER_ELEVATED")]
    [InlineData("volume_up", "MEDIA")]
    [InlineData("brightness_down", "MEDIA")]
    [InlineData("terminal_start", "TERMINAL")]
    public void CapabilityManager_MapCommandToCapability_CorrectMapping(string command, string expectedCap)
    {
        string? cap = CapabilityManager.MapCommandToCapability(command);
        Assert.Equal(expectedCap, cap);
    }

    [Fact]
    public async Task RunWorkflowAsync_OriginatingDeviceWithoutPowerElevated_RejectsUnlockAction()
    {
        var logger = new TestLogger();
        var trustStore = new TrustStore(logger, _testDir);
        
        // Add a trusted device with only AUTOMATION capability
        using var ecdsa1 = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        string spki1 = Convert.ToBase64String(ecdsa1.ExportSubjectPublicKeyInfo());
        var phone = trustStore.AddOrUpdate("dev-auto-only", "AutomationOnlyPhone", spki1, new[] { "AUTOMATION", "MEDIA" }, "2.0");

        var engine = new AutomationEngine(logger, null!, trustStore, _testDir);

        var wf = new TetherWorkflow
        {
            Id = "wf-unauth-unlock",
            Name = "Unauthorized Unlock Workflow",
            OriginatingFingerprint = phone.Fingerprint,
            OriginatingDeviceId = phone.DeviceId,
            Actions = new List<string> { "unlock" }
        };
        engine.SaveWorkflow(wf);

        var result = await engine.RunWorkflowAsync(wf.Id, CancellationToken.None);

        Assert.False(result.Success, "Workflow containing unlock from device without POWER_ELEVATED must fail.");
        Assert.Contains("REJECTED", result.Message);
        Assert.Contains("POWER_ELEVATED", result.Message);
    }

    [Fact]
    public async Task RunWorkflowAsync_RevokedOriginatingDevice_RejectsEntireWorkflow()
    {
        var logger = new TestLogger();
        var trustStore = new TrustStore(logger, _testDir);

        // Do not add the phone to the trust store (simulating revoked/non-existent phone)
        var engine = new AutomationEngine(logger, null!, trustStore, _testDir);

        var wf = new TetherWorkflow
        {
            Id = "wf-revoked-dev",
            Name = "Revoked Device Workflow",
            OriginatingFingerprint = "fp-revoked-device",
            OriginatingDeviceId = "dev-revoked",
            Actions = new List<string> { "volume_up" }
        };
        engine.SaveWorkflow(wf);

        var result = await engine.RunWorkflowAsync(wf.Id, CancellationToken.None);

        Assert.False(result.Success, "Workflow from revoked device must fail immediately.");
        Assert.Contains("revoked or unauthorized", result.Message, StringComparison.OrdinalIgnoreCase);

        var stored = engine.GetWorkflows().Find(w => w.Id == wf.Id);
        Assert.NotNull(stored);
        Assert.Equal("FAILED_REVOKED", stored.LastStatus);
    }

    [Fact]
    public async Task RunWorkflowAsync_OriginatingDeviceWithPowerElevated_AllowsAction()
    {
        var logger = new TestLogger();
        var trustStore = new TrustStore(logger, _testDir);

        using var ecdsa2 = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        string spki2 = Convert.ToBase64String(ecdsa2.ExportSubjectPublicKeyInfo());
        var phone = trustStore.AddOrUpdate("dev-authorized", "AuthorizedPhone", spki2, new[] { "AUTOMATION", "POWER_ELEVATED", "MEDIA" }, "2.0");

        var engine = new AutomationEngine(logger, null!, trustStore, _testDir);

        var wf = new TetherWorkflow
        {
            Id = "wf-auth-actions",
            Name = "Authorized Workflow",
            OriginatingFingerprint = phone.Fingerprint,
            OriginatingDeviceId = phone.DeviceId,
            Actions = new List<string> { "unlock" }
        };
        engine.SaveWorkflow(wf);

        var result = await engine.RunWorkflowAsync(wf.Id, CancellationToken.None);

        Assert.DoesNotContain("REJECTED", result.Message);
        Assert.DoesNotContain("Missing", result.Message);
    }
}
