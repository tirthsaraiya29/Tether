using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Tether.CommunicationService.Capabilities;
using Tether.CommunicationService.Devices;
using Tether.CommunicationService.FileTransfer;
using Tether.CommunicationService.Pairing;
using Tether.CommunicationService.Protocol;
using Tether.CommunicationService.Security;
using Tether.CommunicationService.Sessions;
using Tether.CommunicationService.Transport;
using Tether.CommunicationService.Trust;
using Tether.EventBus;
using Tether.Shared.Logging;
using Xunit;

namespace Tether.Tests;

public class TETH_REG_001_WorkflowRejectionTests
{
    [Theory]
    [InlineData("WORKFLOW_LIST")]
    [InlineData("GET_WORKFLOWS")]
    [InlineData("WORKFLOW_SAVE")]
    [InlineData("SAVE_WORKFLOW")]
    [InlineData("WORKFLOW_DELETE")]
    [InlineData("DELETE_WORKFLOW")]
    [InlineData("WORKFLOW_RUN")]
    [InlineData("RUN_WORKFLOW")]
    public async Task RouteFrameAsync_WorkflowProtocolOperations_AreExplicitlyRejected(string frameType)
    {
        var logger = new TestLogger();
        var capManager = new CapabilityManager(logger);
        var eventBus = new InMemoryEventBus(logger);
        var tokenStore = new TokenStore();
        var inputForwarder = new InputForwarder(logger);
        string tempDir = Path.Combine(Path.GetTempPath(), "Tether_RegTest_" + Guid.NewGuid().ToString("N"));
        var trustStore = new TrustStore(logger, tempDir);
        var deviceManager = new DeviceManager(logger, trustStore);
        var sessionManager = new SessionManager(deviceManager, logger);
        var identity = new WindowsIdentity(logger);
        var pairingManager = new PairingManager(eventBus, logger, identity, deviceManager);

        var router = new PacketRouter(
            logger,
            capManager,
            eventBus,
            tokenStore,
            inputForwarder,
            adminManager: null!,
            sessionManager);

        using var session = new TetherSession(
            eventBus,
            logger,
            identity,
            deviceManager,
            sessionManager,
            pairingManager,
            router,
            inputForwarder);

        using var responseStream = new MemoryStream();
        session.SetStreamForTesting(responseStream);

        var device = new TetherDevice
        {
            DeviceId = "test-device",
            DisplayName = "TestPhone",
            Fingerprint = "test-fingerprint",
            Capabilities = new System.Collections.Generic.List<string> { "*" },
            TrustState = DeviceTrustState.Paired
        };

        string reqId = "test-req-123";
        string jsonPayload = JsonSerializer.Serialize(new { type = frameType, requestId = reqId, id = "wf-1" });
        using var doc = JsonDocument.Parse(jsonPayload);

        await router.RouteFrameAsync(doc, session, device, responseStream, CancellationToken.None);

        responseStream.Seek(0, SeekOrigin.Begin);
        byte[] lenBytes = new byte[4];
        int read = await responseStream.ReadAsync(lenBytes, 0, 4);
        Assert.Equal(4, read);

        int frameLen = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(lenBytes);
        byte[] payloadBytes = new byte[frameLen];
        int payloadRead = await responseStream.ReadAsync(payloadBytes, 0, frameLen);
        Assert.Equal(frameLen, payloadRead);

        using var respDoc = JsonDocument.Parse(payloadBytes);
        var root = respDoc.RootElement;

        Assert.Equal("CONFIRM_ACTION", root.GetProperty("type").GetString());
        Assert.Equal(reqId, root.GetProperty("requestId").GetString());
        Assert.False(root.GetProperty("success").GetBoolean());
        Assert.Equal("Workflow feature not supported", root.GetProperty("reason").GetString());
    }

    [Theory]
    [InlineData("workflow_run")]
    [InlineData("workflow_save")]
    [InlineData("workflow_list")]
    [InlineData("workflow_delete")]
    public void CapabilityManager_MapCommandToCapability_WorkflowCommandsReturnNull(string command)
    {
        string? cap = CapabilityManager.MapCommandToCapability(command);
        Assert.Null(cap);
    }

    [Fact]
    public void CapabilityManager_ElevatedCapabilities_DoesNotContainAutomation()
    {
        var elevated = CapabilityManager.ElevatedCapabilities;
        Assert.DoesNotContain("AUTOMATION", elevated);
    }
}
