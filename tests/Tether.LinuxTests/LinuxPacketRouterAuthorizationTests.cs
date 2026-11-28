using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Tether.EventBus;
using Tether.LinuxDaemon.Capabilities;
using Tether.LinuxDaemon.Config;
using Tether.LinuxDaemon.Devices;
using Tether.LinuxDaemon.FileTransfer;
using Tether.LinuxDaemon.Input;
using Tether.LinuxDaemon.Pairing;
using Tether.LinuxDaemon.Protocol;
using Tether.LinuxDaemon.Security;
using Tether.LinuxDaemon.Sessions;
using Tether.LinuxDaemon.Terminal;
using Tether.LinuxDaemon.Transport;
using Tether.LinuxDaemon.Trust;
using Tether.Shared.Logging;
using Xunit;

namespace Tether.LinuxTests;

public class LinuxPacketRouterAuthorizationTests : IDisposable
{
    private readonly string _testDir;
    private readonly LinuxDaemonConfig _config;
    private readonly ITetherLogger _logger;
    private readonly LinuxTrustStore _trustStore;
    private readonly LinuxDeviceManager _deviceManager;
    private readonly LinuxIdentity _identity;
    private readonly IEventBus _eventBus;
    private readonly LinuxPairingManager _pairingManager;
    private readonly LinuxSessionManager _sessionManager;
    private readonly LinuxTokenStore _tokenStore;
    private readonly LinuxUinputInjector _inputInjector;
    private readonly LinuxTerminalManager _terminalManager;
    private readonly LinuxAdminManager _adminManager;
    private readonly LinuxPamAuthServer _pamServer;
    private readonly LinuxPacketRouter _router;

    public LinuxPacketRouterAuthorizationTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "tether_router_auth_" + Guid.NewGuid().ToString("N"));
        _config = new LinuxDaemonConfig
        {
            DataDir = _testDir,
            RunDir = Path.Combine(_testDir, "run"),
            LogDir = Path.Combine(_testDir, "log"),
            PamSocketPath = Path.Combine(_testDir, "run", "auth.sock")
        };
        Directory.CreateDirectory(_config.RunDir);

        _logger = new SerilogTetherLogger();
        _trustStore = new LinuxTrustStore(_logger, _config);
        _deviceManager = new LinuxDeviceManager(_logger, _trustStore);
        _identity = new LinuxIdentity(_logger, _config);
        _eventBus = new InMemoryEventBus(_logger);
        _pairingManager = new LinuxPairingManager(_eventBus, _logger, _identity, _deviceManager, _trustStore);
        _sessionManager = new LinuxSessionManager(_logger);
        _tokenStore = new LinuxTokenStore();
        _inputInjector = new LinuxUinputInjector(_logger);
        _terminalManager = new LinuxTerminalManager(_logger);
        _adminManager = new LinuxAdminManager(_logger);
        _pamServer = new LinuxPamAuthServer(_logger, _config);

        _router = new LinuxPacketRouter(
            _sessionManager,
            _tokenStore,
            _inputInjector,
            _terminalManager,
            _adminManager,
            _pamServer,
            _logger);
    }

    public void Dispose()
    {
        _identity.Dispose();
        _inputInjector.Dispose();
        _terminalManager.Dispose();
        _pamServer.Dispose();
        try
        {
            if (Directory.Exists(_testDir)) Directory.Delete(_testDir, true);
        }
        catch { }
    }

    private LinuxSession CreateTestSession(MemoryStream pipe, LinuxDevice? device = null)
    {
        var session = new LinuxSession(
            _eventBus,
            _logger,
            _identity,
            _deviceManager,
            _sessionManager,
            _pairingManager,
            _trustStore,
            (frame, s, ct) => _router.RouteFrameAsync(frame, s, ct));

        session.SetStreamForTesting(pipe);
        session.SetDeviceForTesting(device);
        return session;
    }

    [Fact]
    public async Task BinaryInput_DroppedIfUnauthenticated()
    {
        bool injected = false;
        _inputInjector.OnEventInjected = (t, c, v) => injected = true;

        using var pipe = new MemoryStream();
        using var session = CreateTestSession(pipe, device: null); // Unauthenticated session

        byte[] frame = new byte[]
        {
            LinuxUinputInjector.PacketTypeInputEvent,
            LinuxUinputInjector.SubtypeButtonState,
            LinuxUinputInjector.MouseButtonLeft,
            LinuxUinputInjector.ButtonStateDown
        };

        await _router.RouteFrameAsync(frame, session, CancellationToken.None);

        Assert.False(injected);
    }

    [Fact]
    public async Task BinaryInput_RejectedIfLacksInputCapability()
    {
        bool injected = false;
        _inputInjector.OnEventInjected = (t, c, v) => injected = true;

        using var pipe = new MemoryStream();
        var device = new LinuxDevice
        {
            DeviceId = "dev-no-input",
            Capabilities = new List<string> { "MEDIA", "TERMINAL" } // No INPUT
        };
        using var session = CreateTestSession(pipe, device);

        byte[] frame = new byte[]
        {
            LinuxUinputInjector.PacketTypeInputEvent,
            LinuxUinputInjector.SubtypeButtonState,
            LinuxUinputInjector.MouseButtonLeft,
            LinuxUinputInjector.ButtonStateDown
        };

        await _router.RouteFrameAsync(frame, session, CancellationToken.None);

        Assert.False(injected);
    }

    [Fact]
    public async Task BinaryInput_SucceedsWithInputCapability()
    {
        var tcs = new TaskCompletionSource<bool>();
        _inputInjector.OnEventInjected = (t, c, v) => tcs.TrySetResult(true);

        using var pipe = new MemoryStream();
        var device = new LinuxDevice
        {
            DeviceId = "dev-with-input",
            Capabilities = new List<string> { "INPUT", "MEDIA" }
        };
        using var session = CreateTestSession(pipe, device);

        byte[] frame = new byte[]
        {
            LinuxUinputInjector.PacketTypeInputEvent,
            LinuxUinputInjector.SubtypeButtonState,
            LinuxUinputInjector.MouseButtonLeft,
            LinuxUinputInjector.ButtonStateDown
        };

        await _router.RouteFrameAsync(frame, session, CancellationToken.None);

        var completed = await Task.WhenAny(tcs.Task, Task.Delay(2000));
        Assert.Same(tcs.Task, completed);
        Assert.True(await tcs.Task);
    }

    [Fact]
    public async Task CommandExecute_PowerCommand_RequiresPowerElevatedCapability()
    {
        using var pipe = new MemoryStream();
        var device = new LinuxDevice
        {
            DeviceId = "dev-media-only",
            Capabilities = new List<string> { "MEDIA" } // Lacks POWER_ELEVATED
        };
        using var session = CreateTestSession(pipe, device);

        byte[] cmd = Encoding.UTF8.GetBytes("{\"type\":\"COMMAND_EXECUTE\",\"command\":\"shutdown\",\"requestId\":\"req_shut_1\"}");
        await _router.RouteFrameAsync(cmd, session, CancellationToken.None);

        pipe.Position = 0;
        using var doc = await FrameCodec.ReadJsonFrameAsync(pipe, CancellationToken.None);
        Assert.NotNull(doc);
        Assert.Equal("CONFIRM_COMMAND", doc.RootElement.GetProperty("type").GetString());
        Assert.False(doc.RootElement.GetProperty("success").GetBoolean());
        Assert.Equal("ERR_UNAUTHORIZED", doc.RootElement.GetProperty("errorCode").GetString());
        Assert.Contains("POWER_ELEVATED", doc.RootElement.GetProperty("reason").GetString());
    }

    [Fact]
    public async Task CommandExecute_UnlockCommand_SucceedsWithLockCapability()
    {
        using var pipe = new MemoryStream();
        var device = new LinuxDevice
        {
            DeviceId = "dev-lock-cap",
            Capabilities = new List<string> { "LOCK" }
        };
        using var session = CreateTestSession(pipe, device);

        byte[] cmd = Encoding.UTF8.GetBytes("{\"type\":\"COMMAND_EXECUTE\",\"command\":\"unlock\",\"requestId\":\"req_unlock_lock\"}");
        await _router.RouteFrameAsync(cmd, session, CancellationToken.None);

        pipe.Position = 0;
        using var doc = await FrameCodec.ReadJsonFrameAsync(pipe, CancellationToken.None);
        Assert.NotNull(doc);
        Assert.Equal("CONFIRM_COMMAND", doc.RootElement.GetProperty("type").GetString());
        Assert.True(doc.RootElement.GetProperty("success").GetBoolean());
    }

    [Fact]
    public async Task CommandExecute_VolumeCommand_RequiresMediaCapability()
    {
        using var pipe = new MemoryStream();
        var device = new LinuxDevice
        {
            DeviceId = "dev-power-only",
            Capabilities = new List<string> { "POWER_ELEVATED" } // Lacks MEDIA
        };
        using var session = CreateTestSession(pipe, device);

        byte[] cmd = Encoding.UTF8.GetBytes("{\"type\":\"COMMAND_EXECUTE\",\"command\":\"volume_up\",\"requestId\":\"req_vol_1\"}");
        await _router.RouteFrameAsync(cmd, session, CancellationToken.None);

        pipe.Position = 0;
        using var doc = await FrameCodec.ReadJsonFrameAsync(pipe, CancellationToken.None);
        Assert.NotNull(doc);
        Assert.Equal("CONFIRM_COMMAND", doc.RootElement.GetProperty("type").GetString());
        Assert.False(doc.RootElement.GetProperty("success").GetBoolean());
        Assert.Equal("ERR_UNAUTHORIZED", doc.RootElement.GetProperty("errorCode").GetString());
        Assert.Contains("MEDIA", doc.RootElement.GetProperty("reason").GetString());
    }

    [Fact]
    public async Task CommandExecute_UnsupportedCommand_ReturnsErrUnsupported()
    {
        using var pipe = new MemoryStream();
        var device = new LinuxDevice
        {
            DeviceId = "dev-all-caps",
            Capabilities = new List<string> { "POWER_ELEVATED", "MEDIA", "TERMINAL" }
        };
        using var session = CreateTestSession(pipe, device);

        byte[] cmd = Encoding.UTF8.GetBytes("{\"type\":\"COMMAND_EXECUTE\",\"command\":\"destroy_hard_drive\",\"requestId\":\"req_bad_1\"}");
        await _router.RouteFrameAsync(cmd, session, CancellationToken.None);

        pipe.Position = 0;
        using var doc = await FrameCodec.ReadJsonFrameAsync(pipe, CancellationToken.None);
        Assert.NotNull(doc);
        Assert.Equal("CONFIRM_COMMAND", doc.RootElement.GetProperty("type").GetString());
        Assert.False(doc.RootElement.GetProperty("success").GetBoolean());
        Assert.Equal("ERR_UNSUPPORTED", doc.RootElement.GetProperty("errorCode").GetString());
    }

    [Fact]
    public async Task CommandExecute_DuplicateRequest_ReturnsCachedResult()
    {
        using var pipe = new MemoryStream();
        var device = new LinuxDevice
        {
            DeviceId = "dev-unlock",
            Capabilities = new List<string> { "POWER_ELEVATED" }
        };
        using var session = CreateTestSession(pipe, device);

        byte[] cmd = Encoding.UTF8.GetBytes("{\"type\":\"COMMAND_EXECUTE\",\"command\":\"unlock\",\"requestId\":\"req_dedup_1\"}");
        await _router.RouteFrameAsync(cmd, session, CancellationToken.None);

        pipe.Position = 0;
        using var doc1 = await FrameCodec.ReadJsonFrameAsync(pipe, CancellationToken.None);
        Assert.NotNull(doc1);
        Assert.True(doc1.RootElement.GetProperty("success").GetBoolean());

        // Send same request ID again
        pipe.SetLength(0);
        await _router.RouteFrameAsync(cmd, session, CancellationToken.None);

        pipe.Position = 0;
        using var doc2 = await FrameCodec.ReadJsonFrameAsync(pipe, CancellationToken.None);
        Assert.NotNull(doc2);
        Assert.Equal("req_dedup_1", doc2.RootElement.GetProperty("requestId").GetString());
        Assert.True(doc2.RootElement.GetProperty("success").GetBoolean());
    }

    [Fact]
    public async Task CommandExecute_SameRequestIdFromDifferentDevice_IsNotServedFromCache()
    {
        var deviceA = new LinuxDevice
        {
            DeviceId = "dev-a",
            Fingerprint = "FP_DEVICE_A",
            Capabilities = new List<string> { "POWER_ELEVATED" }
        };
        var deviceB = new LinuxDevice
        {
            DeviceId = "dev-b",
            Fingerprint = "FP_DEVICE_B",
            Capabilities = new List<string>() // deliberately lacks POWER_ELEVATED
        };

        using var pipeA = new MemoryStream();
        using var sessionA = CreateTestSession(pipeA, deviceA);
        byte[] frame = Encoding.UTF8.GetBytes("{\"type\":\"COMMAND_EXECUTE\",\"command\":\"unlock\",\"requestId\":\"req_shared_1\"}");
        await _router.RouteFrameAsync(frame, sessionA, CancellationToken.None);

        pipeA.Position = 0;
        using (var docA = await FrameCodec.ReadJsonFrameAsync(pipeA, CancellationToken.None))
        {
            Assert.NotNull(docA);
            Assert.True(docA.RootElement.GetProperty("success").GetBoolean());
        }

        using var pipeB = new MemoryStream();
        using var sessionB = CreateTestSession(pipeB, deviceB);
        await _router.RouteFrameAsync(frame, sessionB, CancellationToken.None);

        pipeB.Position = 0;
        using var docB = await FrameCodec.ReadJsonFrameAsync(pipeB, CancellationToken.None);
        Assert.NotNull(docB);
        Assert.False(docB.RootElement.GetProperty("success").GetBoolean());
        Assert.Contains("Unauthorized", docB.RootElement.GetProperty("reason").GetString());
    }

    [Fact]
    public async Task CommandExecute_FromUnauthenticatedSession_IsRejectedWithoutExecuting()
    {
        using var pipe = new MemoryStream();
        using var session = CreateTestSession(pipe, device: null);

        byte[] frame = Encoding.UTF8.GetBytes("{\"type\":\"COMMAND_EXECUTE\",\"command\":\"shutdown\",\"requestId\":\"req_unauth\"}");
        await _router.RouteFrameAsync(frame, session, CancellationToken.None);

        pipe.Position = 0;
        using var doc = await FrameCodec.ReadJsonFrameAsync(pipe, CancellationToken.None);
        Assert.NotNull(doc);
        Assert.False(doc.RootElement.GetProperty("success").GetBoolean());
        Assert.Equal("ERR_UNAUTHORIZED", doc.RootElement.GetProperty("errorCode").GetString());
    }

    [Fact]
    public async Task UnknownFrameType_IsIgnoredWithoutThrowing()
    {
        using var pipe = new MemoryStream();
        var device = new LinuxDevice { DeviceId = "dev-x", Fingerprint = "FP_X", Capabilities = new List<string> { "MEDIA" } };
        using var session = CreateTestSession(pipe, device);

        byte[] frame = Encoding.UTF8.GetBytes("{\"type\":\"TOTALLY_UNKNOWN_COMMAND\",\"requestId\":\"r1\"}");
        await _router.RouteFrameAsync(frame, session, CancellationToken.None);

        // No response frame is written for unknown types, and the router must not throw.
        Assert.Equal(0, pipe.Length);
    }

    [Fact]
    public async Task TerminalStart_RejectedIfLacksTerminalCapability()
    {
        using var pipe = new MemoryStream();
        var device = new LinuxDevice
        {
            DeviceId = "dev-no-term",
            Capabilities = new List<string> { "MEDIA" }
        };
        using var session = CreateTestSession(pipe, device);

        byte[] cmd = Encoding.UTF8.GetBytes("{\"type\":\"TERMINAL_START\",\"requestId\":\"req_term_1\",\"shellType\":\"bash\"}");
        await _router.RouteFrameAsync(cmd, session, CancellationToken.None);

        pipe.Position = 0;
        using var doc = await FrameCodec.ReadJsonFrameAsync(pipe, CancellationToken.None);
        Assert.NotNull(doc);
        Assert.Equal("TERMINAL_START_RESPONSE", doc.RootElement.GetProperty("type").GetString());
        Assert.False(doc.RootElement.GetProperty("success").GetBoolean());
        Assert.Contains("TERMINAL", doc.RootElement.GetProperty("reason").GetString());
    }

    [Fact]
    public async Task MediaControl_RejectedIfLacksMediaCapability()
    {
        using var pipe = new MemoryStream();
        var device = new LinuxDevice
        {
            DeviceId = "dev-no-media",
            Capabilities = new List<string> { "TERMINAL" }
        };
        using var session = CreateTestSession(pipe, device);

        byte[] cmd = Encoding.UTF8.GetBytes("{\"type\":\"MEDIA_CONTROL\",\"action\":\"play\",\"requestId\":\"req_med_1\"}");
        await _router.RouteFrameAsync(cmd, session, CancellationToken.None);

        pipe.Position = 0;
        using var doc = await FrameCodec.ReadJsonFrameAsync(pipe, CancellationToken.None);
        Assert.NotNull(doc);
        Assert.Equal("CONFIRM_ACTION", doc.RootElement.GetProperty("type").GetString());
        Assert.False(doc.RootElement.GetProperty("success").GetBoolean());
    }

    [Fact]
    public async Task AudioDevicesGet_RejectedIfLacksMediaCapability()
    {
        using var pipe = new MemoryStream();
        var device = new LinuxDevice
        {
            DeviceId = "dev-no-media",
            Capabilities = new List<string> { "TERMINAL" }
        };
        using var session = CreateTestSession(pipe, device);

        byte[] cmd = Encoding.UTF8.GetBytes("{\"type\":\"AUDIO_DEVICES_GET\",\"requestId\":\"req_audio_1\"}");
        await _router.RouteFrameAsync(cmd, session, CancellationToken.None);

        pipe.Position = 0;
        using var doc = await FrameCodec.ReadJsonFrameAsync(pipe, CancellationToken.None);
        Assert.NotNull(doc);
        Assert.Equal("CONFIRM_ACTION", doc.RootElement.GetProperty("type").GetString());
        Assert.False(doc.RootElement.GetProperty("success").GetBoolean());
    }

    [Fact]
    public async Task AudioDevicesGet_ReturnsDeviceList_WhenAuthorized()
    {
        using var pipe = new MemoryStream();
        var device = new LinuxDevice
        {
            DeviceId = "dev-with-media",
            Capabilities = new List<string> { "MEDIA" }
        };
        using var session = CreateTestSession(pipe, device);

        byte[] cmd = Encoding.UTF8.GetBytes("{\"type\":\"AUDIO_DEVICES_GET\",\"requestId\":\"req_audio_2\"}");
        await _router.RouteFrameAsync(cmd, session, CancellationToken.None);

        pipe.Position = 0;
        using var doc = await FrameCodec.ReadJsonFrameAsync(pipe, CancellationToken.None);
        Assert.NotNull(doc);
        Assert.Equal("AUDIO_DEVICES_RESPONSE", doc.RootElement.GetProperty("type").GetString());
        Assert.Equal("req_audio_2", doc.RootElement.GetProperty("requestId").GetString());
        Assert.True(doc.RootElement.TryGetProperty("devices", out var devProp));
        Assert.Equal(JsonValueKind.Array, devProp.ValueKind);
    }

    [Fact]
    public async Task AudioSessionsGet_ReturnsSessionsAndDevices_WhenAuthorized()
    {
        using var pipe = new MemoryStream();
        var device = new LinuxDevice
        {
            DeviceId = "dev-with-media",
            Capabilities = new List<string> { "MEDIA" }
        };
        using var session = CreateTestSession(pipe, device);

        byte[] cmd = Encoding.UTF8.GetBytes("{\"type\":\"AUDIO_SESSIONS_GET\",\"requestId\":\"req_sess_1\"}");
        await _router.RouteFrameAsync(cmd, session, CancellationToken.None);

        pipe.Position = 0;
        using var doc = await FrameCodec.ReadJsonFrameAsync(pipe, CancellationToken.None);
        Assert.NotNull(doc);
        Assert.Equal("AUDIO_SESSIONS_RESPONSE", doc.RootElement.GetProperty("type").GetString());
        Assert.Equal("req_sess_1", doc.RootElement.GetProperty("requestId").GetString());
        Assert.True(doc.RootElement.TryGetProperty("sessions", out _));
        Assert.True(doc.RootElement.TryGetProperty("devices", out _));
        Assert.True(doc.RootElement.TryGetProperty("micGain", out _));
    }

    [Fact]
    public async Task MicGetState_ReturnsMicState_WhenAuthorized()
    {
        using var pipe = new MemoryStream();
        var device = new LinuxDevice
        {
            DeviceId = "dev-with-media",
            Capabilities = new List<string> { "MEDIA" }
        };
        using var session = CreateTestSession(pipe, device);

        byte[] cmd = Encoding.UTF8.GetBytes("{\"type\":\"MIC_GET_STATE\",\"requestId\":\"req_mic_1\"}");
        await _router.RouteFrameAsync(cmd, session, CancellationToken.None);

        pipe.Position = 0;
        using var doc = await FrameCodec.ReadJsonFrameAsync(pipe, CancellationToken.None);
        Assert.NotNull(doc);
        Assert.Equal("MIC_STATE_RESPONSE", doc.RootElement.GetProperty("type").GetString());
        Assert.Equal("req_mic_1", doc.RootElement.GetProperty("requestId").GetString());
        Assert.True(doc.RootElement.TryGetProperty("level", out _));
        Assert.True(doc.RootElement.TryGetProperty("isMuted", out _));
    }
}
