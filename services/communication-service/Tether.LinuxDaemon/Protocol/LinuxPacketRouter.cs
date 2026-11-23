using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Tether.LinuxDaemon.Capabilities;
using Tether.LinuxDaemon.Devices;
using Tether.LinuxDaemon.FileTransfer;
using Tether.LinuxDaemon.Input;
using Tether.LinuxDaemon.Security;
using Tether.LinuxDaemon.Sessions;
using Tether.LinuxDaemon.Terminal;
using Tether.LinuxDaemon.Transport;
using Tether.Shared.Logging;

namespace Tether.LinuxDaemon.Protocol;

public sealed class LinuxPacketRouter
{
    private readonly LinuxSessionManager _sessionManager;
    private readonly LinuxTokenStore _tokenStore;
    private readonly LinuxUinputInjector _inputInjector;
    private readonly LinuxTerminalManager _terminalManager;
    private readonly LinuxAdminManager _adminManager;
    private readonly LinuxPamAuthServer _pamServer;
    private readonly ITetherLogger _logger;

    public LinuxPacketRouter(
        LinuxSessionManager sessionManager,
        LinuxTokenStore tokenStore,
        LinuxUinputInjector inputInjector,
        LinuxTerminalManager terminalManager,
        LinuxAdminManager adminManager,
        LinuxPamAuthServer pamServer,
        ITetherLogger logger)
    {
        _sessionManager = sessionManager;
        _tokenStore = tokenStore;
        _inputInjector = inputInjector;
        _terminalManager = terminalManager;
        _adminManager = adminManager;
        _pamServer = pamServer;
        _logger = logger;

        // Wire terminal output streaming directly to the target device
        _terminalManager.OnOutputReceived = (sessionId, output, dir, ownerDeviceId) =>
        {
            var frameObj = new
            {
                type = "TERMINAL_OUTPUT",
                sessionId = sessionId,
                terminalId = sessionId,
                output = output,
                data = output,
                workingDir = dir,
                deviceId = ownerDeviceId
            };
            string json = JsonSerializer.Serialize(frameObj);
            byte[] bytes = Encoding.UTF8.GetBytes(json);
            _ = _sessionManager.SendRawFrameToDeviceAsync(ownerDeviceId, bytes);
        };
    }

    public async Task RouteFrameAsync(ReadOnlyMemory<byte> rawFrame, LinuxSession session, CancellationToken ct = default)
    {
        if (rawFrame.Length == 0) return;

        var span = rawFrame.Span;

        // 1. Synthetic Input binary packet (0x05)
        if (span[0] == LinuxUinputInjector.PacketTypeInputEvent)
        {
            _inputInjector.Handle(span);
            return;
        }

        // 2. JSON frame
        if (span[0] != (byte)'{')
        {
            _logger.Warning($"LinuxPacketRouter: Unknown frame prefix 0x{span[0]:X2}. Frame ignored.");
            return;
        }

        try
        {
            using var doc = JsonDocument.Parse(rawFrame);
            if (!doc.RootElement.TryGetProperty("type", out var typeProp))
            {
                return;
            }

            string type = typeProp.GetString() ?? "";
            string reqId = doc.RootElement.TryGetProperty("requestId", out var rProp) ? (rProp.GetString() ?? "") : "";
            if (string.IsNullOrEmpty(reqId) || reqId.Length > 64)
            {
                reqId = Guid.NewGuid().ToString("N")[..8];
            }

            string deviceId = session.Device?.DeviceId ?? session.Device?.Fingerprint ?? "unknown-device";

            switch (type)
            {
                case "PING":
                    await session.WriteJsonFrameSafeAsync(new { type = "PONG", timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() }, ct);
                    break;

                case "PONG":
                    session.RecordPongReceived();
                    break;

                case "HANDSHAKE_PROOF":
                    await session.WriteJsonFrameSafeAsync(new { type = "HANDSHAKE_VERIFIED", status = "OK" }, ct);
                    break;

                case "COMMAND_EXECUTE":
                    string command = doc.RootElement.TryGetProperty("command", out var cmdProp) ? (cmdProp.GetString() ?? "") : "";
                    string reqCap = MapCommandToCapability(command);
                    if (!HasCapability(session.Device, reqCap))
                    {
                        _logger.Warning($"LinuxPacketRouter: Rejected '{command}' - device '{deviceId}' lacks capability '{reqCap}'.");
                        await session.WriteJsonFrameSafeAsync(new ConfirmCommand
                        {
                            Type = "CONFIRM_COMMAND",
                            RequestId = reqId,
                            ConfirmedCommand = command,
                            Success = false,
                            Reason = $"Unauthorized: Device lacks {reqCap} capability",
                            VolumeLevel = -1,
                            IsMuted = false,
                            BrightnessLevel = -1
                        }, ct);
                        break;
                    }

                    bool ok = LinuxHardwareExecutor.ExecuteCommand(command, _logger, _pamServer, out int vol);
                    bool isMuted = LinuxHardwareExecutor.GetSystemMute(_logger);
                    int bri = LinuxHardwareExecutor.GetBrightnessLevel(_logger);
                    await session.WriteJsonFrameSafeAsync(new ConfirmCommand
                    {
                        Type = "CONFIRM_COMMAND",
                        RequestId = reqId,
                        ConfirmedCommand = command,
                        Success = ok,
                        Reason = ok ? "OK" : "Execution failed",
                        VolumeLevel = vol >= 0 ? vol : LinuxHardwareExecutor.GetSystemVolumeLevel(_logger),
                        IsMuted = isMuted,
                        BrightnessLevel = bri
                    }, ct);
                    break;

                case "FILE_TRANSFER_TOKEN_REQUEST":
                    if (session.Device == null || !session.Device.Capabilities.Contains("FILES"))
                    {
                        await session.WriteJsonFrameSafeAsync(new
                        {
                            type = "FILE_TRANSFER_TOKEN_RESPONSE",
                            requestId = reqId,
                            success = false,
                            reason = "Unauthorized: device lacks FILES capability"
                        }, ct);
                        break;
                    }
                    var token = _tokenStore.GenerateToken(TimeSpan.FromMinutes(15), session.Device.Fingerprint, session.Device.Capabilities);
                    await session.WriteJsonFrameSafeAsync(new
                    {
                        type = "FILE_TRANSFER_TOKEN_RESPONSE",
                        requestId = reqId,
                        success = true,
                        token = token,
                        validForMinutes = 15
                    }, ct);
                    break;

                // Terminal Frames
                case "TERMINAL_START":
                    if (!HasCapability(session.Device, "TERMINAL"))
                    {
                        _logger.Warning($"LinuxPacketRouter: Rejected terminal request - device '{deviceId}' lacks TERMINAL capability.");
                        await session.WriteJsonFrameSafeAsync(new
                        {
                            type = "TERMINAL_START_RESPONSE",
                            requestId = reqId,
                            success = false,
                            reason = "Unauthorized: Device lacks TERMINAL capability",
                            deviceId = deviceId
                        }, ct);
                        break;
                    }

                    string shell = doc.RootElement.TryGetProperty("shell", out var shProp) ? (shProp.GetString() ?? "bash")
                        : (doc.RootElement.TryGetProperty("shellType", out var stProp) ? (stProp.GetString() ?? "bash") : "bash");
                    string? initialDir = doc.RootElement.TryGetProperty("initialDir", out var idProp) ? idProp.GetString()
                        : (doc.RootElement.TryGetProperty("workingDir", out var wdProp) ? wdProp.GetString() : null);
                    string? termId = doc.RootElement.TryGetProperty("terminalId", out var tidProp) ? tidProp.GetString()
                        : (doc.RootElement.TryGetProperty("sessionId", out var sidProp) ? sidProp.GetString() : null);

                    try
                    {
                        var tInfo = _terminalManager.StartSession(shell, initialDir, termId, deviceId);
                        await session.WriteJsonFrameSafeAsync(new
                        {
                            type = "TERMINAL_START_RESPONSE",
                            requestId = reqId,
                            terminal = tInfo,
                            sessionId = tInfo.Id,
                            deviceId = deviceId,
                            success = true
                        }, ct);
                    }
                    catch (Exception ex)
                    {
                        await session.WriteJsonFrameSafeAsync(new
                        {
                            type = "TERMINAL_START_RESPONSE",
                            requestId = reqId,
                            success = false,
                            reason = ex.Message,
                            deviceId = deviceId
                        }, ct);
                    }
                    break;

                case "TERMINAL_INPUT":
                    if (!HasCapability(session.Device, "TERMINAL")) break;
                    string termSessId = doc.RootElement.TryGetProperty("sessionId", out var inSidProp) ? (inSidProp.GetString() ?? "")
                        : (doc.RootElement.TryGetProperty("terminalId", out var inTidProp) ? (inTidProp.GetString() ?? "") : "");
                    string inData = doc.RootElement.TryGetProperty("data", out var dProp) ? (dProp.GetString() ?? "") : "";
                    _terminalManager.SendInput(termSessId, inData, deviceId);
                    break;

                case "TERMINAL_CLOSE":
                    if (!HasCapability(session.Device, "TERMINAL")) break;
                    string closeId = doc.RootElement.TryGetProperty("sessionId", out var cSidProp) ? (cSidProp.GetString() ?? "")
                        : (doc.RootElement.TryGetProperty("terminalId", out var cTidProp) ? (cTidProp.GetString() ?? "") : "");
                    bool closed = _terminalManager.CloseSession(closeId, deviceId);
                    await session.WriteJsonFrameSafeAsync(new
                    {
                        type = "TERMINAL_SESSION_CLOSED",
                        sessionId = closeId,
                        terminalId = closeId,
                        deviceId = deviceId,
                        success = closed
                    }, ct);
                    break;

                case "TERMINAL_LIST":
                    if (!HasCapability(session.Device, "TERMINAL"))
                    {
                        await session.WriteJsonFrameSafeAsync(new { type = "TERMINAL_LIST_RESPONSE", requestId = reqId, sessions = Array.Empty<object>(), deviceId = deviceId }, ct);
                        break;
                    }
                    var tList = _terminalManager.ListSessions(deviceId);
                    await session.WriteJsonFrameSafeAsync(new
                    {
                        type = "TERMINAL_LIST_RESPONSE",
                        requestId = reqId,
                        sessions = tList,
                        deviceId = deviceId
                    }, ct);
                    break;

                // Desktop Notification Frames
                case "NOTIFICATION_EVENT":
                    if (!HasCapability(session.Device, "NOTIFICATIONS")) break;
                    string nTitle = doc.RootElement.TryGetProperty("title", out var ntProp) ? (ntProp.GetString() ?? "") : "";
                    string nBody = doc.RootElement.TryGetProperty("body", out var nbProp) ? (nbProp.GetString() ?? "") : "";
                    string nApp = doc.RootElement.TryGetProperty("app", out var naProp) ? (naProp.GetString() ?? "Phone") : "Phone";
                    _ = LinuxNotificationController.ShowNotificationOnDesktopAsync(nTitle, nBody, nApp, _logger);
                    break;

                case "NOTIFICATION_DISMISS":
                    if (!HasCapability(session.Device, "NOTIFICATIONS")) break;
                    if (doc.RootElement.TryGetProperty("id", out var nidProp) && nidProp.TryGetUInt32(out uint notifId))
                    {
                        _ = LinuxNotificationController.DismissNotificationAsync(notifId, _logger);
                    }
                    break;

                // Media Frames
                case "MEDIA_CONTROL":
                    if (!HasCapability(session.Device, "MEDIA"))
                    {
                        await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Unauthorized: Device lacks MEDIA capability" }, ct);
                        break;
                    }
                    string mediaAction = doc.RootElement.TryGetProperty("action", out var mActProp) ? (mActProp.GetString() ?? "") : "";
                    long? seek = doc.RootElement.TryGetProperty("seek", out var skProp) ? skProp.GetInt64()
                        : (doc.RootElement.TryGetProperty("seekSeconds", out var sksProp) ? sksProp.GetInt64() : null);
                    bool mediaOk = await LinuxMediaController.ExecuteMediaControlAsync(mediaAction, seek, _logger);
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = mediaOk }, ct);
                    break;

                case "MEDIA_GET_METADATA":
                    if (!HasCapability(session.Device, "MEDIA"))
                    {
                        await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Unauthorized: Device lacks MEDIA capability" }, ct);
                        break;
                    }
                    var meta = await LinuxMediaController.GetCurrentMetadataAsync(_logger);
                    await session.WriteJsonFrameSafeAsync(new
                    {
                        type = "MEDIA_METADATA_UPDATE",
                        requestId = reqId,
                        title = meta.Title,
                        artist = meta.Artist,
                        album = meta.Album,
                        isPlaying = meta.IsPlaying,
                        position = meta.PositionSeconds,
                        duration = meta.DurationSeconds,
                        thumbnail = meta.ThumbnailBase64
                    }, ct);
                    break;

                // Application Management Frames
                case "APP_LAUNCH":
                    if (!HasCapability(session.Device, "APP_LAUNCH"))
                    {
                        await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Unauthorized: Device lacks APP_LAUNCH capability" }, ct);
                        break;
                    }
                    string appLaunchName = doc.RootElement.TryGetProperty("appName", out var alProp) ? (alProp.GetString() ?? "")
                        : (doc.RootElement.TryGetProperty("appPath", out var apProp) ? (apProp.GetString() ?? "") : "");
                    bool lOk = await LinuxApplicationManager.LaunchAppAsync(appLaunchName, _logger);
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = lOk }, ct);
                    break;

                case "APP_GET_INSTALLED":
                case "GET_INSTALLED_APPS":
                    if (!HasCapability(session.Device, "APP_LAUNCH"))
                    {
                        await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Unauthorized: Device lacks APP_LAUNCH capability" }, ct);
                        break;
                    }
                    var installedApps = LinuxApplicationManager.GetInstalledApps(_logger);
                    await session.WriteJsonFrameSafeAsync(new
                    {
                        type = "APP_INSTALLED_RESPONSE",
                        requestId = reqId,
                        apps = installedApps
                    }, ct);
                    break;

                case "APP_GET_WINDOWS":
                case "GET_RUNNING_WINDOWS":
                    if (!HasCapability(session.Device, "APP_LAUNCH"))
                    {
                        await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Unauthorized: Device lacks APP_LAUNCH capability" }, ct);
                        break;
                    }
                    var windows = LinuxApplicationManager.GetRunningWindows(_logger);
                    await session.WriteJsonFrameSafeAsync(new
                    {
                        type = "WINDOWS_LIST_RESPONSE",
                        requestId = reqId,
                        windows = windows
                    }, ct);
                    break;

                case "APP_CLOSE_WINDOW":
                case "WINDOW_CLOSE":
                    if (!HasCapability(session.Device, "APP_LAUNCH"))
                    {
                        await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Unauthorized: Device lacks APP_LAUNCH capability" }, ct);
                        break;
                    }
                    string winId = doc.RootElement.TryGetProperty("id", out var wIdProp) ? (wIdProp.GetString() ?? "")
                        : (doc.RootElement.TryGetProperty("hwnd", out var hProp) ? hProp.ToString() : "");
                    bool closeOk = await LinuxApplicationManager.CloseWindowAsync(winId, _logger);
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = closeOk }, ct);
                    break;

                // Linux System Administration Telemetry
                case "ADMIN_TELEMETRY_GET":
                case "GET_ADMIN_TELEMETRY":
                    if (!HasCapability(session.Device, "ADMIN"))
                    {
                        await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Unauthorized: Device lacks ADMIN capability" }, ct);
                        break;
                    }
                    var telem = _adminManager.GetSystemTelemetry();
                    await session.WriteJsonFrameSafeAsync(new { type = "ADMIN_TELEMETRY_RESPONSE", requestId = reqId, telemetry = telem }, ct);
                    break;

                case "HARDWARE_SPECS_GET":
                case "GET_HARDWARE_SPECS":
                    if (!HasCapability(session.Device, "ADMIN"))
                    {
                        await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Unauthorized: Device lacks ADMIN capability" }, ct);
                        break;
                    }
                    var specs = _adminManager.GetHardwareSpecs();
                    await session.WriteJsonFrameSafeAsync(new { type = "HARDWARE_SPECS_RESPONSE", requestId = reqId, specs = specs }, ct);
                    break;

                case "BATTERY_HEALTH_GET":
                case "GET_BATTERY_HEALTH":
                    if (!HasCapability(session.Device, "ADMIN"))
                    {
                        await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Unauthorized: Device lacks ADMIN capability" }, ct);
                        break;
                    }
                    var bHealth = _adminManager.GetBatteryHealth();
                    await session.WriteJsonFrameSafeAsync(new { type = "BATTERY_HEALTH_RESPONSE", requestId = reqId, batteryHealth = bHealth }, ct);
                    break;

                case "POWER_PLANS_GET":
                case "GET_POWER_PLANS":
                    if (!HasCapability(session.Device, "ADMIN"))
                    {
                        await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Unauthorized: Device lacks ADMIN capability" }, ct);
                        break;
                    }
                    var pPlans = _adminManager.GetPowerPlans();
                    await session.WriteJsonFrameSafeAsync(new { type = "POWER_PLANS_RESPONSE", requestId = reqId, powerPlans = pPlans }, ct);
                    break;

                case "SET_POWER_PLAN":
                    if (!HasCapability(session.Device, "ADMIN"))
                    {
                        await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Unauthorized: Device lacks ADMIN capability" }, ct);
                        break;
                    }
                    string plan = doc.RootElement.TryGetProperty("planGuid", out var pgProp) ? (pgProp.GetString() ?? "")
                        : (doc.RootElement.TryGetProperty("name", out var pnProp) ? (pnProp.GetString() ?? "") : "");
                    bool pOk = _adminManager.SetPowerPlan(plan);
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = pOk }, ct);
                    break;

                case "USB_DEVICES_GET":
                case "GET_USB_DEVICES":
                    if (!HasCapability(session.Device, "ADMIN"))
                    {
                        await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Unauthorized: Device lacks ADMIN capability" }, ct);
                        break;
                    }
                    var usb = _adminManager.GetUsbDevices();
                    await session.WriteJsonFrameSafeAsync(new { type = "USB_DEVICES_RESPONSE", requestId = reqId, usbDevices = usb }, ct);
                    break;

                case "SERVICES_GET":
                case "GET_SERVICES":
                    if (!HasCapability(session.Device, "ADMIN"))
                    {
                        await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Unauthorized: Device lacks ADMIN capability" }, ct);
                        break;
                    }
                    var services = _adminManager.GetServices();
                    await session.WriteJsonFrameSafeAsync(new { type = "SERVICES_RESPONSE", requestId = reqId, services = services }, ct);
                    break;

                case "SERVICE_START":
                case "SERVICE_STOP":
                case "SERVICE_RESTART":
                    if (!HasCapability(session.Device, "ADMIN"))
                    {
                        await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Unauthorized: Device lacks ADMIN capability" }, ct);
                        break;
                    }
                    string sName = doc.RootElement.TryGetProperty("serviceName", out var snProp) ? (snProp.GetString() ?? "") : "";
                    string sAction = type == "SERVICE_START" ? "start" : (type == "SERVICE_STOP" ? "stop" : "restart");
                    bool sOk = _adminManager.ControlService(sName, sAction);
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = sOk }, ct);
                    break;

                case "UPDATES_GET":
                case "GET_UPDATES":
                    if (!HasCapability(session.Device, "ADMIN"))
                    {
                        await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Unauthorized: Device lacks ADMIN capability" }, ct);
                        break;
                    }
                    var updates = _adminManager.GetSystemUpdates();
                    await session.WriteJsonFrameSafeAsync(new { type = "UPDATES_RESPONSE", requestId = reqId, updateInfo = updates }, ct);
                    break;

                case "LAPTOP_STATE_GET":
                case "GET_LAPTOP_STATE":
                    var state = LinuxLaptopStateCollector.GetLaptopState(_logger);
                    await session.WriteJsonFrameSafeAsync(state, ct);
                    break;

                default:
                    _logger.Warning($"LinuxPacketRouter: Unhandled packet type '{type}'.");
                    break;
            }
        }
        catch (Exception ex)
        {
            _logger.Error($"LinuxPacketRouter: Error processing packet: {ex.Message}");
        }
    }

    private static bool HasCapability(LinuxDevice? device, string requiredCap)
    {
        if (device == null || string.IsNullOrEmpty(requiredCap)) return false;
        if (device.Capabilities.Contains("*")) return true;
        if (device.Capabilities.Contains(requiredCap, StringComparer.OrdinalIgnoreCase)) return true;

        if (requiredCap.Equals("APP_LAUNCH", StringComparison.OrdinalIgnoreCase) &&
            device.Capabilities.Contains("APP_MANAGEMENT", StringComparer.OrdinalIgnoreCase))
            return true;

        if (requiredCap.Equals("POWER_ELEVATED", StringComparison.OrdinalIgnoreCase) &&
            (device.Capabilities.Contains("SYSTEM_UNLOCK", StringComparer.OrdinalIgnoreCase) ||
             device.Capabilities.Contains("SYSTEM_CONTROL", StringComparer.OrdinalIgnoreCase)))
            return true;

        if (requiredCap.Equals("ADMIN", StringComparison.OrdinalIgnoreCase) &&
            (device.Capabilities.Contains("LINUX_ADMIN", StringComparer.OrdinalIgnoreCase) ||
             device.Capabilities.Contains("WINDOWS_ADMIN", StringComparer.OrdinalIgnoreCase)))
            return true;

        return false;
    }

    private static string MapCommandToCapability(string command)
    {
        string cmd = command.Trim().ToLowerInvariant();
        if (cmd is "unlock") return "POWER_ELEVATED";
        if (cmd is "shutdown" or "poweroff" or "halt" or "reboot" or "restart" or "sleep" or "suspend" or "hibernate")
            return "POWER_ELEVATED";
        if (cmd.StartsWith("admin_") || cmd.StartsWith("service_") || cmd.StartsWith("power_plan"))
            return "ADMIN";
        if (cmd.StartsWith("launch_") || cmd is "browser" or "calc" or "terminal")
            return "APP_LAUNCH";
        return "MEDIA";
    }
}
