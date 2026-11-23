using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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

    private readonly ConcurrentDictionary<string, (int Count, long WindowStartMs)> _inputRateLimits = new();
    private readonly ConcurrentDictionary<string, (long TimestampMs, ConfirmCommand Result)> _recentCommandResults = new();

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

        // Wire terminal session exit notification to target device
        _terminalManager.OnSessionExited = (sessionId, ownerDeviceId) =>
        {
            var frameObj = new
            {
                type = "TERMINAL_SESSION_CLOSED",
                sessionId = sessionId,
                terminalId = sessionId,
                deviceId = ownerDeviceId,
                success = true,
                reason = "Process exited"
            };
            string json = JsonSerializer.Serialize(frameObj);
            byte[] bytes = Encoding.UTF8.GetBytes(json);
            _ = _sessionManager.SendRawFrameToDeviceAsync(ownerDeviceId, bytes);
        };
    }

    private bool CheckInputRateLimit(string sessionId, int maxEventsPerSec = 500)
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var (count, windowStart) = _inputRateLimits.GetOrAdd(sessionId, (0, now));
        if (now - windowStart > 1000)
        {
            _inputRateLimits[sessionId] = (1, now);
            return true;
        }
        if (count >= maxEventsPerSec)
        {
            return false;
        }
        _inputRateLimits[sessionId] = (count + 1, windowStart);
        return true;
    }

    private void CleanupRecentCommandResults()
    {
        if (_recentCommandResults.Count > 500)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var expired = _recentCommandResults
                .Where(kv => now - kv.Value.TimestampMs > 60_000)
                .Select(kv => kv.Key)
                .ToList();
            foreach (var k in expired) _recentCommandResults.TryRemove(k, out _);
        }
    }

    public async Task RouteFrameAsync(ReadOnlyMemory<byte> rawFrame, LinuxSession session, CancellationToken ct = default)
    {
        if (rawFrame.Length == 0) return;

        var span = rawFrame.Span;

        // 1. Synthetic Input binary packet (0x05) - requires authenticated session and INPUT capability
        if (span[0] == LinuxUinputInjector.PacketTypeInputEvent)
        {
            if (session.Device == null)
            {
                _logger.Warning($"LinuxPacketRouter: Dropped binary input from unauthenticated session [{session.SessionId}].");
                return;
            }

            if (!HasCapability(session.Device, "INPUT"))
            {
                _logger.Warning($"LinuxPacketRouter: Rejected binary input: device '{session.Device.Fingerprint}' lacks INPUT capability.");
                return;
            }

            if (span.Length < 2)
            {
                _logger.Warning($"LinuxPacketRouter: Truncated binary input packet ({span.Length} bytes).");
                return;
            }

            if (!CheckInputRateLimit(session.SessionId))
            {
                _logger.Warning($"LinuxPacketRouter: Input rate limit exceeded for session [{session.SessionId}].");
                return;
            }

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

                    if (session.Device == null)
                    {
                        _logger.Warning($"LinuxPacketRouter: Rejected '{command}' from unauthenticated session [{session.SessionId}].");
                        await session.WriteJsonFrameSafeAsync(new ConfirmCommand
                        {
                            Type = "CONFIRM_COMMAND",
                            RequestId = reqId,
                            ConfirmedCommand = command,
                            Success = false,
                            Reason = "Unauthorized: Session is not authenticated",
                            ErrorCode = "ERR_UNAUTHORIZED",
                            State = "REJECTED",
                            VolumeLevel = -1,
                            IsMuted = false,
                            BrightnessLevel = -1
                        }, ct);
                        break;
                    }

                    // Check for duplicate command execution (deduplication)
                    CleanupRecentCommandResults();
                    if (_recentCommandResults.TryGetValue(reqId, out var existingResult))
                    {
                        _logger.Info($"LinuxPacketRouter: Returning deduplicated cached result for reqId '{reqId}' ({command}).");
                        await session.WriteJsonFrameSafeAsync(existingResult.Result, ct);
                        break;
                    }

                    string reqCap = MapCommandToCapability(command);
                    if (!HasCapability(session.Device, reqCap))
                    {
                        _logger.Warning($"LinuxPacketRouter: Rejected '{command}' - device '{deviceId}' lacks capability '{reqCap}'.");
                        var rejConfirm = new ConfirmCommand
                        {
                            Type = "CONFIRM_COMMAND",
                            RequestId = reqId,
                            ConfirmedCommand = command,
                            Success = false,
                            Reason = $"Unauthorized: Device lacks {reqCap} capability",
                            ErrorCode = "ERR_UNAUTHORIZED",
                            State = "REJECTED",
                            VolumeLevel = -1,
                            IsMuted = false,
                            BrightnessLevel = -1
                        };
                        await session.WriteJsonFrameSafeAsync(rejConfirm, ct);
                        break;
                    }

                    if (!IsRecognizedHardwareCommand(command))
                    {
                        _logger.Warning($"LinuxPacketRouter: Unsupported hardware command '{command}'.");
                        var unsuppConfirm = new ConfirmCommand
                        {
                            Type = "CONFIRM_COMMAND",
                            RequestId = reqId,
                            ConfirmedCommand = command,
                            Success = false,
                            Reason = $"Unsupported command '{command}'",
                            ErrorCode = "ERR_UNSUPPORTED",
                            State = "FAILED",
                            VolumeLevel = -1,
                            IsMuted = false,
                            BrightnessLevel = -1
                        };
                        await session.WriteJsonFrameSafeAsync(unsuppConfirm, ct);
                        break;
                    }

                    bool ok = LinuxHardwareExecutor.ExecuteCommand(command, _logger, _pamServer, out int vol);
                    bool isMuted = false;
                    int bri = -1;
                    int finalVol = vol;

                    string lowerCmd = command.Trim().ToLowerInvariant();
                    if (lowerCmd.Contains("volume") || lowerCmd.Contains("vol") || lowerCmd.Contains("mute"))
                    {
                        isMuted = LinuxHardwareExecutor.GetSystemMute(_logger);
                        finalVol = vol >= 0 ? vol : LinuxHardwareExecutor.GetSystemVolumeLevel(_logger);
                    }
                    else if (lowerCmd.Contains("bright"))
                    {
                        bri = LinuxHardwareExecutor.GetBrightnessLevel(_logger);
                    }

                    var confirm = new ConfirmCommand
                    {
                        Type = "CONFIRM_COMMAND",
                        RequestId = reqId,
                        ConfirmedCommand = command,
                        Success = ok,
                        Reason = ok ? "OK" : "Execution failed",
                        ErrorCode = ok ? null : "ERR_EXECUTION_FAILED",
                        State = ok ? "COMPLETED" : "FAILED",
                        VolumeLevel = finalVol,
                        IsMuted = isMuted,
                        BrightnessLevel = bri
                    };
                    _recentCommandResults[reqId] = (DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), confirm);
                    await session.WriteJsonFrameSafeAsync(confirm, ct);
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

                case "APP_SWITCH_WINDOW":
                case "WINDOW_FOCUS":
                    if (!HasCapability(session.Device, "APP_LAUNCH"))
                    {
                        await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Unauthorized: Device lacks APP_LAUNCH capability" }, ct);
                        break;
                    }
                    string focusWinId = doc.RootElement.TryGetProperty("id", out var fwIdProp) ? (fwIdProp.GetString() ?? "")
                        : (doc.RootElement.TryGetProperty("hwnd", out var fhProp) ? fhProp.ToString() : "");
                    bool focusOk = await LinuxApplicationManager.ActivateWindowAsync(focusWinId, _logger);
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = focusOk }, ct);
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

                case "AUDIO_DEVICES_GET":
                case "GET_AUDIO_DEVICES":
                    if (!HasCapability(session.Device, "MEDIA"))
                    {
                        await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Unauthorized: Device lacks MEDIA capability" }, ct);
                        break;
                    }
                    var audioDevs = LinuxHardwareExecutor.GetAudioDevices(_logger);
                    await session.WriteJsonFrameSafeAsync(new
                    {
                        type = "AUDIO_DEVICES_RESPONSE",
                        requestId = reqId,
                        devices = audioDevs
                    }, ct);
                    break;

                case "AUDIO_SESSIONS_GET":
                case "GET_AUDIO_SESSIONS":
                    if (!HasCapability(session.Device, "MEDIA"))
                    {
                        await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Unauthorized: Device lacks MEDIA capability" }, ct);
                        break;
                    }
                    var audioSessions = LinuxHardwareExecutor.GetAppAudioSessions(_logger);
                    var currentDevs = LinuxHardwareExecutor.GetAudioDevices(_logger);
                    var micState = LinuxHardwareExecutor.GetMicrophoneState(_logger);
                    bool masterMuted = LinuxHardwareExecutor.GetSystemMute(_logger);
                    await session.WriteJsonFrameSafeAsync(new
                    {
                        type = "AUDIO_SESSIONS_RESPONSE",
                        requestId = reqId,
                        sessions = audioSessions,
                        devices = currentDevs,
                        masterMuted = masterMuted,
                        micMuted = micState.isMuted,
                        micGain = micState.gain
                    }, ct);
                    break;

                case "AUDIO_DEFAULT_DEVICE_SET":
                case "SET_AUDIO_DEVICE":
                    if (!HasCapability(session.Device, "MEDIA"))
                    {
                        await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Unauthorized: Device lacks MEDIA capability" }, ct);
                        break;
                    }
                    string devId = doc.RootElement.TryGetProperty("deviceId", out var diProp) ? (diProp.GetString() ?? "") : "";
                    bool isDevInput = doc.RootElement.TryGetProperty("isInput", out var iiProp) && iiProp.GetBoolean();
                    bool devOk = LinuxHardwareExecutor.SetDefaultAudioDevice(devId, isDevInput, _logger);
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = devOk }, ct);
                    break;

                case "MIC_GET_STATE":
                case "GET_MIC_STATE":
                    if (!HasCapability(session.Device, "MEDIA"))
                    {
                        await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Unauthorized: Device lacks MEDIA capability" }, ct);
                        break;
                    }
                    var micInfo = LinuxHardwareExecutor.GetMicrophoneState(_logger);
                    await session.WriteJsonFrameSafeAsync(new { type = "MIC_STATE_RESPONSE", requestId = reqId, level = micInfo.gain, isMuted = micInfo.isMuted }, ct);
                    break;

                case "MIC_SET_STATE":
                case "SET_MIC_GAIN":
                case "SET_MIC_MUTE":
                    if (!HasCapability(session.Device, "MEDIA"))
                    {
                        await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Unauthorized: Device lacks MEDIA capability" }, ct);
                        break;
                    }
                    int micLvl = doc.RootElement.TryGetProperty("level", out var mlProp) ? mlProp.GetInt32() : (doc.RootElement.TryGetProperty("gain", out var gProp) ? gProp.GetInt32() : -1);
                    bool? micMt = doc.RootElement.TryGetProperty("isMuted", out var mmProp) ? mmProp.GetBoolean() : (doc.RootElement.TryGetProperty("mute", out var muProp) ? muProp.GetBoolean() : null);
                    bool micSetOk = LinuxHardwareExecutor.SetMicrophoneState(micLvl, micMt, _logger);
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = micSetOk }, ct);
                    break;

                case "AUDIO_APP_VOLUME_SET":
                case "SET_APP_VOLUME":
                    if (!HasCapability(session.Device, "MEDIA"))
                    {
                        await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Unauthorized: Device lacks MEDIA capability" }, ct);
                        break;
                    }
                    string appVolId = doc.RootElement.TryGetProperty("id", out var avidProp) ? (avidProp.GetString() ?? "") : (doc.RootElement.TryGetProperty("pid", out var avpProp) ? avpProp.ToString() : "");
                    int appVol = doc.RootElement.TryGetProperty("volume", out var avProp) ? avProp.GetInt32() : (doc.RootElement.TryGetProperty("volumePercent", out var avpctProp) ? avpctProp.GetInt32() : 100);
                    bool avOk = LinuxHardwareExecutor.SetAppVolume(appVolId, appVol, _logger);
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = avOk }, ct);
                    break;

                case "AUDIO_APP_MUTE_SET":
                case "SET_APP_MUTE":
                    if (!HasCapability(session.Device, "MEDIA"))
                    {
                        await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Unauthorized: Device lacks MEDIA capability" }, ct);
                        break;
                    }
                    string appMtId = doc.RootElement.TryGetProperty("id", out var amidProp) ? (amidProp.GetString() ?? "") : (doc.RootElement.TryGetProperty("pid", out var ampProp) ? ampProp.ToString() : "");
                    bool appMt = doc.RootElement.TryGetProperty("isMuted", out var aimProp) ? aimProp.GetBoolean() : (doc.RootElement.TryGetProperty("mute", out var amProp) && amProp.GetBoolean());
                    bool amOk = LinuxHardwareExecutor.SetAppMute(appMtId, appMt, _logger);
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = amOk }, ct);
                    break;

                case "CHECK_UPDATES":
                    await session.WriteJsonFrameSafeAsync(new
                    {
                        type = "UPDATES_RESPONSE",
                        requestId = reqId,
                        updateInfo = new { hasUpdates = false }
                    }, ct);
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
             device.Capabilities.Contains("SYSTEM_CONTROL", StringComparer.OrdinalIgnoreCase) ||
             device.Capabilities.Contains("LOCK", StringComparer.OrdinalIgnoreCase)))
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
        if (cmd is "shutdown" or "poweroff" or "halt" or "reboot" or "restart" or "sleep" or "suspend" or "hibernate" or "panic" or "panic_lock")
            return "POWER_ELEVATED";
        if (cmd.StartsWith("admin_") || cmd.StartsWith("service_") || cmd.StartsWith("power_plan"))
            return "ADMIN";
        if (cmd.StartsWith("launch_") || cmd is "browser" or "calc" or "terminal")
            return "APP_LAUNCH";
        return "MEDIA";
    }

    private static bool IsRecognizedHardwareCommand(string command)
    {
        string cmd = command.Trim().ToLowerInvariant();
        if (cmd is "lock" or "lock_workstation" or "lock_now" or "unlock"
            or "sleep" or "suspend" or "hibernate" or "reboot" or "restart"
            or "shutdown" or "poweroff" or "halt" or "panic" or "panic_lock")
            return true;
        if (cmd is "volume_mute" or "vol_mute" or "mute" or "volume_up" or "vol_up" or "volume_down" or "vol_down" or "volume_get" or "get_volume")
            return true;
        if (cmd.StartsWith("set_volume:") || cmd.StartsWith("volume_set:") || cmd.StartsWith("vol_set:"))
            return true;
        if (cmd is "brightness_up" or "bright_up" or "brightness_down" or "bright_down" or "brightness_get" or "get_brightness")
            return true;
        if (cmd.StartsWith("set_brightness:") || cmd.StartsWith("brightness_set:") || cmd.StartsWith("bright_set:"))
            return true;
        if (cmd is "laptop_state_get" or "get_laptop_state")
            return true;
        return false;
    }
}
