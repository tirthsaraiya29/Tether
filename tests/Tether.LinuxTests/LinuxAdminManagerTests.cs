using System;
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

public class LinuxAdminManagerTests : IDisposable
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

    public LinuxAdminManagerTests()
    {
        _testDir = Path.Combine(Path.GetTempPath(), "tether_admin_test_" + Guid.NewGuid().ToString("N"));
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

    [Fact]
    public void TestTelemetryAndSpecs()
    {
        var telem = _adminManager.GetSystemTelemetry();
        Assert.InRange(telem.CpuUsage, 0, 100);
        Assert.True(telem.TotalRamMb > 0);
        Assert.InRange(telem.RamUsagePct, 0, 100);
        Assert.True(telem.UptimeSeconds >= 0);
        Assert.NotEmpty(telem.Disks);
        Assert.All(telem.Disks, d => Assert.True(d.TotalGb > 0));

        var specs = _adminManager.GetHardwareSpecs();
        Assert.NotEmpty(specs.ProcessorName);
        Assert.True(specs.CoreCount >= 1);
        Assert.Contains("Linux", specs.OsDescription);

        // Contract check: the Android client reads these exact camelCase keys.
        var json = JsonSerializer.Serialize(telem, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        using var doc = JsonDocument.Parse(json);
        foreach (var key in new[] { "cpuUsage", "totalRamMb", "availRamMb", "ramUsagePct", "disks", "networks", "cpuCores", "uptimeSeconds" })
        {
            Assert.True(doc.RootElement.TryGetProperty(key, out _), $"missing telemetry key {key}");
        }

        var specsJson = JsonSerializer.Serialize(specs, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        using var specsDoc = JsonDocument.Parse(specsJson);
        foreach (var key in new[] { "processorName", "coreCount", "totalMemoryMb", "osDescription", "uptimeSeconds" })
        {
            Assert.True(specsDoc.RootElement.TryGetProperty(key, out _), $"missing specs key {key}");
        }
    }

    [Fact]
    public void TestBatteryAndPowerPlans()
    {
        var bHealth = _adminManager.GetBatteryHealth();
        Assert.NotNull(bHealth);
        Assert.InRange(bHealth.WearLevelPercent, 0, 100);

        // Plans must come from a real backend (power-profiles-daemon / ACPI / cpufreq).
        // An empty list on a host without any of them is correct; fabricated entries are not.
        var plans = _adminManager.GetPowerPlans();
        Assert.All(plans, p => Assert.False(string.IsNullOrWhiteSpace(p.Guid)));
        if (plans.Count > 0)
        {
            Assert.Contains(plans, p => p.IsActive);
        }

        Assert.False(_adminManager.SetPowerPlan("definitely-not-a-real-profile"));
        Assert.False(_adminManager.SetPowerPlan(""));
    }

    [Fact]
    public void TestUsbAndServices()
    {
        var usb = _adminManager.GetUsbDevices();
        Assert.NotNull(usb);

        var services = _adminManager.GetServices();
        Assert.NotNull(services);
        // On systemd machines, services list must have units
        if (services.Count > 0)
        {
            Assert.Contains(services, s => !string.IsNullOrEmpty(s.ServiceName));
        }
    }

    [Theory]
    [InlineData("sshd; rm -rf /", "stop")]
    [InlineData("../../etc/passwd", "start")]
    [InlineData("", "start")]
    [InlineData("systemd-logind", "stop")]
    [InlineData("tether", "stop")]
    [InlineData("sshd", "disable")]
    [InlineData("sshd", "stop --now")]
    public void ControlService_RejectsMalformedProtectedOrUnknownActions(string unit, string action)
    {
        Assert.False(_adminManager.ControlService(unit, action));
    }

    [Fact]
    public void BatteryReport_IsHonestWhenNoBatteryExists()
    {
        var report = _adminManager.GenerateBatteryReport();
        Assert.NotNull(report);
        if (!report.Success)
        {
            Assert.NotEmpty(report.ErrorMessage);
        }
        else
        {
            Assert.NotEmpty(report.ReportTimestamp);
        }
    }

    [Fact]
    public void UpdateCheck_ReturnsAStatusWithoutThrowing()
    {
        var info = _adminManager.GetSystemUpdates();
        Assert.NotNull(info);
        Assert.False(string.IsNullOrWhiteSpace(info.StatusMessage));
        if (info.CheckSucceeded)
            Assert.Equal(info.Titles.Count, info.PendingUpdatesCount);
        else
            Assert.Equal(-1, info.PendingUpdatesCount); // failure must not read as "0 updates"
    }

    [Fact]
    public async Task Router_HandlesPingAndTelemetryRequests()
    {
        using var pipe = new MemoryStream();
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
        session.SetDeviceForTesting(new Tether.LinuxDaemon.Devices.LinuxDevice
        {
            DeviceId = "test-admin-phone",
            DisplayName = "Test Phone",
            Capabilities = new List<string> { "ADMIN", "MEDIA" }
        });

        // Send PING
        byte[] pingBytes = Encoding.UTF8.GetBytes("{\"type\":\"PING\"}");
        await _router.RouteFrameAsync(pingBytes, session, CancellationToken.None);

        // Pipe should contain written response frame
        pipe.Position = 0;
        using var doc = await FrameCodec.ReadJsonFrameAsync(pipe, CancellationToken.None);
        Assert.NotNull(doc);
        Assert.Equal("PONG", doc.RootElement.GetProperty("type").GetString());

        // Send LAPTOP_STATE_GET
        pipe.SetLength(0);
        byte[] stateReq = Encoding.UTF8.GetBytes("{\"type\":\"LAPTOP_STATE_GET\"}");
        await _router.RouteFrameAsync(stateReq, session, CancellationToken.None);

        pipe.Position = 0;
        using var stateDoc = await FrameCodec.ReadJsonFrameAsync(pipe, CancellationToken.None);
        Assert.NotNull(stateDoc);
        Assert.Equal("LAPTOP_STATE", stateDoc.RootElement.GetProperty("type").GetString());

        // Send ADMIN_TELEMETRY_GET
        pipe.SetLength(0);
        byte[] telemReq = Encoding.UTF8.GetBytes("{\"type\":\"ADMIN_TELEMETRY_GET\",\"requestId\":\"req_1\"}");
        await _router.RouteFrameAsync(telemReq, session, CancellationToken.None);

        pipe.Position = 0;
        using var telemDoc = await FrameCodec.ReadJsonFrameAsync(pipe, CancellationToken.None);
        Assert.NotNull(telemDoc);
        Assert.Equal("ADMIN_TELEMETRY_RESPONSE", telemDoc.RootElement.GetProperty("type").GetString());
        Assert.True(telemDoc.RootElement.TryGetProperty("telemetry", out _));
    }

    [Fact]
    public async Task Router_UnauthorizedDevice_WithoutAdminCapability_IsRejected()
    {
        using var pipe = new MemoryStream();
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
        session.SetDeviceForTesting(new Tether.LinuxDaemon.Devices.LinuxDevice
        {
            DeviceId = "unauthorized-phone",
            DisplayName = "Restricted Phone",
            Capabilities = new List<string> { "MEDIA" } // Lacks ADMIN and POWER_ELEVATED
        });

        // Attempt ADMIN_TELEMETRY_GET without ADMIN capability
        byte[] telemReq = Encoding.UTF8.GetBytes("{\"type\":\"ADMIN_TELEMETRY_GET\",\"requestId\":\"req_unauth\"}");
        await _router.RouteFrameAsync(telemReq, session, CancellationToken.None);

        pipe.Position = 0;
        using var telemDoc = await FrameCodec.ReadJsonFrameAsync(pipe, CancellationToken.None);
        Assert.NotNull(telemDoc);
        Assert.Equal("CONFIRM_ACTION", telemDoc.RootElement.GetProperty("type").GetString());
        Assert.False(telemDoc.RootElement.GetProperty("success").GetBoolean());
        Assert.Contains("Unauthorized", telemDoc.RootElement.GetProperty("reason").GetString());

        // Attempt COMMAND_EXECUTE (unlock) without POWER_ELEVATED capability
        pipe.SetLength(0);
        byte[] cmdReq = Encoding.UTF8.GetBytes("{\"type\":\"COMMAND_EXECUTE\",\"command\":\"unlock\",\"requestId\":\"cmd_unauth\"}");
        await _router.RouteFrameAsync(cmdReq, session, CancellationToken.None);

        pipe.Position = 0;
        using var cmdDoc = await FrameCodec.ReadJsonFrameAsync(pipe, CancellationToken.None);
        Assert.NotNull(cmdDoc);
        Assert.Equal("CONFIRM_COMMAND", cmdDoc.RootElement.GetProperty("type").GetString());
        Assert.False(cmdDoc.RootElement.GetProperty("success").GetBoolean());
        Assert.Contains("Unauthorized", cmdDoc.RootElement.GetProperty("reason").GetString());
    }
}
