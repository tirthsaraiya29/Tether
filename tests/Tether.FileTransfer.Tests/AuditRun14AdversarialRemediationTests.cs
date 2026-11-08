using Tether.SessionHelper;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using Tether.CommunicationService.Automation;
using Tether.CommunicationService.Capabilities;
using Tether.CommunicationService.Devices;
using Tether.Shared.Logging;
using Xunit;

namespace Tether.FileTransfer.Tests;

public class AuditRun14AdversarialRemediationTests
{
    [Fact]
    public void CapabilityManager_MediaRole_StrictlyDoesNotGrantAdminOrAutomation()
    {
        var logger = new MockLogger();
        var capManager = new CapabilityManager(logger);

        var mediaDevice = new TetherDevice
        {
            DeviceId = "media-phone",
            DisplayName = "Standard Paired Media Phone",
            Capabilities = new List<string> { "MEDIA", "FILES", "APP_LAUNCH" }
        };

        // Standard commands
        Assert.True(capManager.CanDeviceExecuteCommand(mediaDevice, "volume_up"));
        Assert.True(capManager.CanDeviceExecuteCommand(mediaDevice, "brightness_down"));
        Assert.True(capManager.CanDeviceExecuteCommand(mediaDevice, "launch_browser"));

        // Administrative, power, and automation commands must be STRICTLY rejected
        Assert.False(capManager.CanDeviceExecuteCommand(mediaDevice, "admin_telemetry_get"));
        Assert.False(capManager.CanDeviceExecuteCommand(mediaDevice, "service_stop"));
        Assert.False(capManager.CanDeviceExecuteCommand(mediaDevice, "power_plan_set"));
        Assert.False(capManager.CanDeviceExecuteCommand(mediaDevice, "workflow_run"));
        Assert.False(capManager.CanDeviceExecuteCommand(mediaDevice, "shutdown"));
        Assert.False(capManager.CanDeviceExecuteCommand(mediaDevice, "reboot"));

        Assert.False(capManager.HasCapability(mediaDevice, "WINDOWS_ADMIN"));
        Assert.False(capManager.HasCapability(mediaDevice, "AUTOMATION"));
        Assert.False(capManager.HasCapability(mediaDevice, "POWER_ELEVATED"));
    }

    [Fact]
    public void CapabilityManager_AdminAndAutomation_RequireExplicitOrElevatedRoles()
    {
        var logger = new MockLogger();
        var capManager = new CapabilityManager(logger);

        var adminDevice = new TetherDevice
        {
            DeviceId = "admin-phone",
            DisplayName = "Admin Phone",
            Capabilities = new List<string> { "WINDOWS_ADMIN", "AUTOMATION", "APP_MANAGEMENT" }
        };

        Assert.True(capManager.CanDeviceExecuteCommand(adminDevice, "admin_telemetry_get"));
        Assert.True(capManager.CanDeviceExecuteCommand(adminDevice, "workflow_list"));
        Assert.True(capManager.CanDeviceExecuteCommand(adminDevice, "app_launch"));

        Assert.True(capManager.HasCapability(adminDevice, "WINDOWS_ADMIN"));
        Assert.True(capManager.HasCapability(adminDevice, "AUTOMATION"));
        Assert.True(capManager.HasCapability(adminDevice, "APP_MANAGEMENT"));
    }

    [Fact]
    public async Task AutomationEngine_ConditionEvaluation_FailsClosedForInvalidOrUnknownConditions()
    {
        var logger = new MockLogger();
        var adminMgr = new WindowsAdminManager(logger);
        var engine = new AutomationEngine(logger, adminMgr);

        // A workflow with an invalid threshold must NOT execute its actions
        var invalidWf = new TetherWorkflow
        {
            Id = "test_invalid_wf",
            Name = "Invalid Condition Workflow",
            ConditionType = "battery_below",
            ConditionValue = "not_a_valid_number",
            Actions = new List<string> { "volume_mute" }
        };

        engine.SaveWorkflow(invalidWf);
        var result = await engine.RunWorkflowAsync("test_invalid_wf", default);

        Assert.True(result.Success);
        Assert.Contains("Condition not met", result.Message);

        // Unknown condition type must fail closed
        var unknownWf = new TetherWorkflow
        {
            Id = "test_unknown_wf",
            Name = "Unknown Condition Workflow",
            ConditionType = "unsupported_gpu_temp_above",
            ConditionValue = "80",
            Actions = new List<string> { "volume_mute" }
        };

        engine.SaveWorkflow(unknownWf);
        var resultUnknown = await engine.RunWorkflowAsync("test_unknown_wf", default);

        Assert.True(resultUnknown.Success);
        Assert.Contains("Condition not met", resultUnknown.Message);

        engine.DeleteWorkflow("test_invalid_wf");
        engine.DeleteWorkflow("test_unknown_wf");
    }

    [Fact]
    public void SerializationDTOs_ExposeCrossPlatformPropertyAliases()
    {
        var app = new InstalledAppInfo
        {
            Name = "Chrome",
            ShortcutPath = @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Chrome.lnk"
        };
        Assert.Equal(app.ShortcutPath, app.Path);

        string appJson = JsonSerializer.Serialize(app);
        using var appDoc = JsonDocument.Parse(appJson);
        Assert.True(appDoc.RootElement.TryGetProperty("Path", out var pProp) || appDoc.RootElement.TryGetProperty("ShortcutPath", out _));

        var audio = new AppAudioSession
        {
            ProcessId = 1234,
            ProcessName = "spotify",
            VolumePercent = 75,
            IsMuted = false
        };
        Assert.Equal(audio.ProcessId, audio.Pid);

        var win = new RunningWindowInfo
        {
            Hwnd = 987654L,
            Title = "Terminal",
            ProcessId = 4321
        };
        Assert.Equal(win.ProcessId, win.Pid);

        var term = new TerminalSessionInfo
        {
            Id = "term_session_1",
            ShellType = "powershell.exe"
        };
        Assert.Equal(term.Id, term.SessionId);
    }
}
