using System;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Tether.CommunicationService.Automation;
using Tether.CommunicationService.Capabilities;
using Tether.CommunicationService.Devices;
using Tether.CommunicationService.FileTransfer;
using Tether.CommunicationService.Sessions;
using Tether.CommunicationService.Transport;
using Tether.EventBus;
using Tether.Shared.Events;
using Tether.Shared.Logging;

namespace Tether.CommunicationService.Protocol;

public sealed class PacketRouter
{
    private readonly ITetherLogger _logger;
    private readonly CapabilityManager _capabilityManager;
    private readonly IEventBus _eventBus;
    private readonly TokenStore _tokenStore;
    private readonly InputForwarder _inputForwarder;
    private readonly WindowsAdminManager _adminManager;
    private readonly AutomationEngine _automationEngine;
    private readonly SessionManager _sessionManager;

    public PacketRouter(
        ITetherLogger logger,
        CapabilityManager capabilityManager,
        IEventBus eventBus,
        TokenStore tokenStore,
        InputForwarder inputForwarder,
        WindowsAdminManager adminManager,
        AutomationEngine automationEngine,
        SessionManager sessionManager)
    {
        _logger = logger;
        _capabilityManager = capabilityManager;
        _eventBus = eventBus;
        _tokenStore = tokenStore;
        _inputForwarder = inputForwarder;
        _adminManager = adminManager;
        _automationEngine = automationEngine;
        _sessionManager = sessionManager;

        // Relay events from SessionHelper (Windows desktop) to connected phone sessions
        _inputForwarder.OnHelperEventReceived += rawJson =>
        {
            try
            {
                using var doc = JsonDocument.Parse(rawJson);
                string type = doc.RootElement.TryGetProperty("type", out var tProp) ? (tProp.GetString() ?? "") : "";
                if (type == "TERMINAL_OUTPUT")
                {
                    string targetDeviceId = doc.RootElement.TryGetProperty("deviceId", out var dProp) ? (dProp.GetString() ?? "") : "";
                    if (!string.IsNullOrWhiteSpace(targetDeviceId))
                    {
                        _sessionManager.SendRawFrameToDevice(targetDeviceId, rawJson);
                    }
                    else
                    {
                        Console.WriteLine("[Security Alert] TERMINAL_OUTPUT frame dropped: missing target deviceId. Refusing to broadcast.");
                    }
                    return;
                }

                _sessionManager.BroadcastRawFrame(rawJson);
            }
            catch (Exception ex)
            {
                if (rawJson != null && (rawJson.Contains("TERMINAL_OUTPUT", StringComparison.OrdinalIgnoreCase) ||
                                       rawJson.Contains("terminalId", StringComparison.OrdinalIgnoreCase)))
                {
                    Console.WriteLine($"[Security Alert] Rejected unparseable terminal frame: {ex.Message}");
                    return;
                }

                Console.WriteLine($"[PacketRouter] Error processing helper event: {ex.Message}");
            }
        };
    }

    public async Task RouteFrameAsync(JsonDocument doc, TetherSession session, TetherDevice device, Stream stream, CancellationToken ct)
    {
        string type;
        try { type = doc.RootElement.GetProperty("type").GetString() ?? ""; }
        catch { return; }

        string reqId = doc.RootElement.TryGetProperty("requestId", out var rProp) ? (rProp.GetString() ?? "") : "";
        if (string.IsNullOrEmpty(reqId))
        {
            reqId = Guid.NewGuid().ToString("N")[..8];
        }

        switch (type)
        {
            case "PING":
                _logger.Debug($"PacketRouter: Received PING from '{device.DisplayName}'. Responding with PONG.");
                await session.WriteJsonFrameSafeAsync(new { type = "PONG", timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() }, ct);
                break;

            case "PONG":
                _logger.Debug($"PacketRouter: Received PONG from '{device.DisplayName}'.");
                session.RecordPongReceived();
                break;

            case "HANDSHAKE_PROOF":
                _logger.Debug($"PacketRouter: Received HANDSHAKE_PROOF from '{device.DisplayName}'. Responding with HANDSHAKE_VERIFIED.");
                await session.WriteJsonFrameSafeAsync(new { type = "HANDSHAKE_VERIFIED", status = "OK" }, ct);
                break;

            case "HANDSHAKE_VERIFIED":
                _logger.Debug($"PacketRouter: Received HANDSHAKE_VERIFIED from '{device.DisplayName}'.");
                break;

            case "COMMAND_EXECUTE":
                await HandleCommandAsync(doc, session, device, stream, ct);
                break;

            case "FILE_TRANSFER_TOKEN_REQUEST":
                _logger.Info($"PacketRouter: Received FILE_TRANSFER_TOKEN_REQUEST from '{device.DisplayName}'. Generating token for fingerprint '{device.Fingerprint}'.");
                var token = _tokenStore.GenerateToken(TimeSpan.FromMinutes(60), device.Fingerprint);
                await session.WriteJsonFrameSafeAsync(new { type = "FILE_TRANSFER_TOKEN_RESPONSE", requestId = reqId, token = token, validForMinutes = 60 }, ct);
                break;

            case "FS_LIST_RESULT":
            case "FS_DOWNLOAD_RESULT":
            case "FS_UPLOAD_RESULT":
            case "FS_TRANSFER_STATUS":
                FileTransferServer.HandleRemoteResponse(type, doc.RootElement.GetRawText());
                break;

            // Terminal Frames
            case "TERMINAL_START":
            case "TERMINAL_INPUT":
            case "TERMINAL_CLOSE":
            case "TERMINAL_LIST":
                if (!_capabilityManager.CanDeviceExecuteCommand(device, "terminal_input"))
                {
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Terminal capability required" }, ct);
                    return;
                }

                var termPayload = JsonSerializer.Deserialize<Dictionary<string, object>>(doc.RootElement.GetRawText()) ?? new();
                termPayload["deviceId"] = device.DeviceId;

                if (type == "TERMINAL_START" || type == "TERMINAL_LIST")
                {
                    string? tRes = await _inputForwarder.RequestAsync(termPayload, reqId, TimeSpan.FromSeconds(5), ct);
                    if (tRes != null)
                    {
                        await session.WriteRawFrameSafeAsync(System.Text.Encoding.UTF8.GetBytes(tRes), ct);
                    }
                }
                else
                {
                    _inputForwarder.PostToHelper(termPayload);
                }
                break;

            // Clipboard Frames
            case "CLIPBOARD_SYNC":
            case "CLIPBOARD_SET":
            case "CLIPBOARD_GET":
            case "CLIPBOARD_SIMULATE_COPY":
            case "CLIPBOARD_SIMULATE_PASTE":
                if (!_capabilityManager.CanDeviceExecuteCommand(device, "clipboard"))
                {
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Clipboard capability required" }, ct);
                    return;
                }
                if (type == "CLIPBOARD_GET")
                {
                    string? cRes = await _inputForwarder.RequestAsync(new { type = "CLIPBOARD_GET", requestId = reqId }, reqId, TimeSpan.FromSeconds(3), ct);
                    if (cRes != null)
                    {
                        await session.WriteRawFrameSafeAsync(System.Text.Encoding.UTF8.GetBytes(cRes), ct);
                    }
                }
                else
                {
                    _inputForwarder.PostToHelper(JsonSerializer.Deserialize<object>(doc.RootElement.GetRawText())!);
                    if (reqId != "")
                    {
                        await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = true }, ct);
                    }
                }
                break;

            // Notification Frames
            case "NOTIFICATION_EVENT": // Mirrored from phone to PC
                if (!_capabilityManager.HasCapability(device, "NOTIFICATIONS"))
                {
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Notifications capability required" }, ct);
                    break;
                }
                string nTitle = doc.RootElement.TryGetProperty("title", out var ntProp) ? (ntProp.GetString() ?? "") : "";
                string nBody = doc.RootElement.TryGetProperty("body", out var nbProp) ? (nbProp.GetString() ?? "") : "";
                string nApp = doc.RootElement.TryGetProperty("app", out var naProp) ? (naProp.GetString() ?? "") : "Phone";
                _inputForwarder.PostToHelper(new { type = "NOTIFICATION_SHOW_DESKTOP", title = nTitle, body = nBody, app = nApp });
                break;

            case "NOTIFICATION_DISMISS":
                if (!_capabilityManager.HasCapability(device, "NOTIFICATIONS"))
                {
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Notifications capability required" }, ct);
                    break;
                }
                _inputForwarder.PostToHelper(JsonSerializer.Deserialize<object>(doc.RootElement.GetRawText())!);
                break;

            // Fast-path Media & Audio Setters (Instant Fire-and-Forget, zero socket latency)
            case "MEDIA_CONTROL":
            case "AUDIO_APP_VOLUME_SET":
            case "SET_APP_VOLUME":
            case "AUDIO_APP_MUTE_SET":
            case "SET_APP_MUTE":
            case "AUDIO_DEFAULT_DEVICE_SET":
            case "SET_AUDIO_DEVICE":
            case "MIC_SET_STATE":
            case "SET_MIC_GAIN":
            case "SET_MIC_MUTE":
                if (!_capabilityManager.HasCapability(device, "MEDIA"))
                {
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Media capability required" }, ct);
                    break;
                }
                _inputForwarder.PostToHelper(JsonSerializer.Deserialize<object>(doc.RootElement.GetRawText())!);
                break;

            // Media & Audio Queries (Asynchronous, Non-Blocking)
            case "MEDIA_GET_METADATA":
            case "AUDIO_SESSIONS_GET":
            case "AUDIO_DEVICES_GET":
            case "MIC_GET_STATE":
                if (!_capabilityManager.HasCapability(device, "MEDIA"))
                {
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Media capability required" }, ct);
                    break;
                }
                {
                    var reqPayload = JsonSerializer.Deserialize<Dictionary<string, object>>(doc.RootElement.GetRawText()) ?? new();
                    reqPayload["requestId"] = reqId;
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            string? mRes = await _inputForwarder.RequestAsync(reqPayload, reqId, TimeSpan.FromSeconds(5), ct);
                            if (mRes != null)
                            {
                                await session.WriteRawFrameSafeAsync(System.Text.Encoding.UTF8.GetBytes(mRes), ct);
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.Warning($"Audio query {type} error: {ex.Message}");
                        }
                    }, ct);
                }
                break;

            // Fast-path Window Setters (Instant Fire-and-Forget)
            case "APP_LAUNCH":
            case "APP_SWITCH_WINDOW":
            case "WINDOW_FOCUS":
            case "WINDOW_SNAP":
            case "APP_SET_WINDOW_STATE":
            case "WINDOW_STATE":
            case "APP_CLOSE_WINDOW":
            case "WINDOW_CLOSE":
                if (!_capabilityManager.HasCapability(device, "APP_MANAGEMENT"))
                {
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "App management capability required" }, ct);
                    break;
                }
                _inputForwarder.PostToHelper(JsonSerializer.Deserialize<object>(doc.RootElement.GetRawText())!);
                break;

            // App Management Queries (Asynchronous, Non-Blocking)
            case "APP_GET_INSTALLED":
            case "APP_GET_WINDOWS":
            case "GET_RUNNING_WINDOWS":
                if (!_capabilityManager.HasCapability(device, "APP_MANAGEMENT"))
                {
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "App management capability required" }, ct);
                    break;
                }
                {
                    var reqPayload = JsonSerializer.Deserialize<Dictionary<string, object>>(doc.RootElement.GetRawText()) ?? new();
                    reqPayload["requestId"] = reqId;
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            string? aRes = await _inputForwarder.RequestAsync(reqPayload, reqId, TimeSpan.FromSeconds(5), ct);
                            if (aRes != null)
                            {
                                await session.WriteRawFrameSafeAsync(System.Text.Encoding.UTF8.GetBytes(aRes), ct);
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.Warning($"App query {type} error: {ex.Message}");
                        }
                    }, ct);
                }
                break;

            // Windows Administration Frames
            case "ADMIN_TELEMETRY_GET":
            case "GET_ADMIN_TELEMETRY":
                if (!_capabilityManager.HasCapability(device, "WINDOWS_ADMIN"))
                {
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Windows admin capability required" }, ct);
                    break;
                }
                var telemetry = _adminManager.GetSystemTelemetry();
                await session.WriteJsonFrameSafeAsync(new { type = "ADMIN_TELEMETRY_RESPONSE", requestId = reqId, telemetry }, ct);
                break;

            case "HARDWARE_SPECS_GET":
            case "GET_HARDWARE_SPECS":
                if (!_capabilityManager.HasCapability(device, "WINDOWS_ADMIN"))
                {
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Windows admin capability required" }, ct);
                    break;
                }
                var specs = _adminManager.GetHardwareSpecs();
                await session.WriteJsonFrameSafeAsync(new { type = "HARDWARE_SPECS_RESPONSE", requestId = reqId, specs }, ct);
                break;

            case "BATTERY_HEALTH_GET":
            case "GET_BATTERY_HEALTH":
                if (!_capabilityManager.HasCapability(device, "WINDOWS_ADMIN"))
                {
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Windows admin capability required" }, ct);
                    break;
                }
                var bHealth = _adminManager.GetBatteryHealth();
                await session.WriteJsonFrameSafeAsync(new { type = "BATTERY_HEALTH_RESPONSE", requestId = reqId, batteryHealth = bHealth }, ct);
                break;

            case "BATTERY_REPORT_GENERATE":
            case "GENERATE_BATTERY_REPORT":
                if (!_capabilityManager.HasCapability(device, "WINDOWS_ADMIN"))
                {
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Windows admin capability required" }, ct);
                    break;
                }
                _ = Task.Run(async () =>
                {
                    try
                    {
                        var bReport = _adminManager.GenerateBatteryReport();
                        await session.WriteJsonFrameSafeAsync(new { type = "BATTERY_REPORT_RESPONSE", requestId = reqId, batteryReport = bReport }, ct);
                    }
                    catch (Exception ex)
                    {
                        _logger.Warning($"Battery report generation error: {ex.Message}");
                    }
                }, ct);
                break;

            case "POWER_PLANS_GET":
            case "GET_POWER_PLANS":
                if (!_capabilityManager.HasCapability(device, "WINDOWS_ADMIN"))
                {
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Windows admin capability required" }, ct);
                    break;
                }
                var plans = _adminManager.GetPowerPlans();
                await session.WriteJsonFrameSafeAsync(new { type = "POWER_PLANS_RESPONSE", requestId = reqId, powerPlans = plans, plans }, ct);
                break;

            case "POWER_PLAN_SET":
            case "SET_POWER_PLAN":
                if (!_capabilityManager.HasCapability(device, "WINDOWS_ADMIN"))
                {
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Windows admin capability required" }, ct);
                    break;
                }
                string pGuid = doc.RootElement.TryGetProperty("guid", out var gProp) ? (gProp.GetString() ?? "") : (doc.RootElement.TryGetProperty("planId", out var piProp) ? (piProp.GetString() ?? "") : "");
                bool pOk = _adminManager.SetActivePowerPlan(pGuid);
                await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = pOk }, ct);
                break;

            case "PRINTERS_GET":
            case "GET_PRINTERS":
                if (!_capabilityManager.HasCapability(device, "WINDOWS_ADMIN"))
                {
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Windows admin capability required" }, ct);
                    break;
                }
                var printers = _adminManager.GetPrinters();
                await session.WriteJsonFrameSafeAsync(new { type = "PRINTERS_RESPONSE", requestId = reqId, printers }, ct);
                break;

            case "USB_DEVICES_GET":
            case "GET_USB_DEVICES":
                if (!_capabilityManager.HasCapability(device, "WINDOWS_ADMIN"))
                {
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Windows admin capability required" }, ct);
                    break;
                }
                var usbList = _adminManager.GetUsbDevices();
                await session.WriteJsonFrameSafeAsync(new { type = "USB_DEVICES_RESPONSE", requestId = reqId, usbDevices = usbList, devices = usbList }, ct);
                break;

            case "SERVICES_GET":
            case "GET_SERVICES":
                if (!_capabilityManager.HasCapability(device, "WINDOWS_ADMIN"))
                {
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Windows admin capability required" }, ct);
                    break;
                }
                string? sFilter = doc.RootElement.TryGetProperty("filter", out var fProp) ? fProp.GetString() : (doc.RootElement.TryGetProperty("search", out var sfProp) ? sfProp.GetString() : null);
                _ = Task.Run(async () =>
                {
                    try
                    {
                        var services = _adminManager.GetServices(sFilter);
                        await session.WriteJsonFrameSafeAsync(new { type = "SERVICES_RESPONSE", requestId = reqId, services }, ct);
                    }
                    catch (Exception ex)
                    {
                        _logger.Warning($"Services get error: {ex.Message}");
                    }
                }, ct);
                break;

            case "SERVICE_CONTROL":
            case "CONTROL_SERVICE":
                if (!_capabilityManager.HasCapability(device, "WINDOWS_ADMIN"))
                {
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Windows admin capability required" }, ct);
                    break;
                }
                string sName = doc.RootElement.TryGetProperty("serviceName", out var snProp) ? (snProp.GetString() ?? "") : (doc.RootElement.TryGetProperty("service", out var sProp) ? (sProp.GetString() ?? "") : "");
                string sAction = doc.RootElement.GetProperty("action").GetString() ?? "";
                bool sOk = _adminManager.ControlService(sName, sAction);
                await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = sOk }, ct);
                break;

            case "UPDATES_CHECK":
            case "CHECK_UPDATES":
                if (!_capabilityManager.HasCapability(device, "WINDOWS_ADMIN"))
                {
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Windows admin capability required" }, ct);
                    break;
                }
                _ = Task.Run(async () =>
                {
                    try
                    {
                        var updates = _adminManager.CheckWindowsUpdates();
                        await session.WriteJsonFrameSafeAsync(new { type = "UPDATES_RESPONSE", requestId = reqId, updates }, ct);
                    }
                    catch (Exception ex)
                    {
                        _logger.Warning($"Windows update check error: {ex.Message}");
                    }
                }, ct);
                break;

            // Automation Frames
            case "WORKFLOW_LIST":
            case "GET_WORKFLOWS":
                if (!_capabilityManager.HasCapability(device, "AUTOMATION"))
                {
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Automation capability required" }, ct);
                    break;
                }
                var wfList = _automationEngine.GetWorkflows();
                await session.WriteJsonFrameSafeAsync(new { type = "WORKFLOW_LIST_RESPONSE", requestId = reqId, workflows = wfList }, ct);
                break;

            case "WORKFLOW_SAVE":
            case "SAVE_WORKFLOW":
                if (!_capabilityManager.HasCapability(device, "AUTOMATION"))
                {
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Automation capability required" }, ct);
                    break;
                }
                var wfObj = JsonSerializer.Deserialize<TetherWorkflow>(doc.RootElement.GetProperty("workflow").GetRawText());
                if (wfObj != null) _automationEngine.SaveWorkflow(wfObj);
                await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = wfObj != null }, ct);
                break;

            case "WORKFLOW_DELETE":
            case "DELETE_WORKFLOW":
                if (!_capabilityManager.HasCapability(device, "AUTOMATION"))
                {
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Automation capability required" }, ct);
                    break;
                }
                string wfDelId = doc.RootElement.GetProperty("id").GetString() ?? "";
                bool delOk = _automationEngine.DeleteWorkflow(wfDelId);
                await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = delOk }, ct);
                break;

            case "WORKFLOW_RUN":
            case "RUN_WORKFLOW":
                if (!_capabilityManager.HasCapability(device, "AUTOMATION"))
                {
                    await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_ACTION", requestId = reqId, success = false, reason = "Automation capability required" }, ct);
                    break;
                }
                string wfRunId = doc.RootElement.GetProperty("id").GetString() ?? "";
                var runRes = await _automationEngine.RunWorkflowAsync(wfRunId, ct);
                await session.WriteJsonFrameSafeAsync(new { type = "WORKFLOW_STATUS", requestId = reqId, result = runRes }, ct);
                break;

            default:
                _logger.Debug($"PacketRouter: Unhandled frame type '{type}' from '{device.DisplayName}'.");
                break;
        }
    }

    private async Task HandleCommandAsync(JsonDocument doc, TetherSession session, TetherDevice device, Stream stream, CancellationToken ct)
    {
        CommandExecute? cmd;
        try { cmd = JsonSerializer.Deserialize<CommandExecute>(doc.RootElement.GetRawText()); }
        catch { return; }

        if (cmd == null || string.IsNullOrEmpty(cmd.Command)) return;

        if (!_capabilityManager.CanDeviceExecuteCommand(device, cmd.Command))
        {
            _logger.Warning($"PacketRouter: Capability check failed for command '{cmd.Command}' from '{device.DisplayName}'.");
            await session.WriteJsonFrameSafeAsync(new
            {
                type = "CONFIRM_COMMAND",
                confirmedCommand = cmd.Command,
                success = false,
                reason = "Capability check failed"
            }, ct);
            return;
        }

        _logger.Info($"PacketRouter: Command accepted for '{device.DisplayName}': {cmd.Command} (requestId={cmd.RequestId}).");

        string cmdLower = cmd.Command.Trim().ToLowerInvariant();
        if (cmdLower is "clipboard_copy")
        {
            _inputForwarder.PostToHelper(new { type = "CLIPBOARD_SIMULATE_COPY" });
            await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_COMMAND", confirmedCommand = cmd.Command, success = true, reason = "OK" }, ct);
            return;
        }
        if (cmdLower is "clipboard_paste")
        {
            _inputForwarder.PostToHelper(new { type = "CLIPBOARD_SIMULATE_PASTE" });
            await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_COMMAND", confirmedCommand = cmd.Command, success = true, reason = "OK" }, ct);
            return;
        }
        if (cmdLower is "notification_dismiss")
        {
            _inputForwarder.PostToHelper(JsonSerializer.Deserialize<object>(doc.RootElement.GetRawText())!);
            await session.WriteJsonFrameSafeAsync(new { type = "CONFIRM_COMMAND", confirmedCommand = cmd.Command, success = true, reason = "OK" }, ct);
            return;
        }

        if (cmdLower is "laptop_state_get" or "get_laptop_state" or "laptop_state")
        {
            _logger.Info($"PacketRouter: Building LAPTOP_STATE snapshot for '{device.DisplayName}'.");

            LaptopSnapshot snap;
            try
            {
                snap = LaptopStateCollector.GetLaptopSnapshot(_logger);
            }
            catch (Exception ex)
            {
                _logger.Warning($"PacketRouter: LaptopSnapshot collection failed: {ex.Message}");
                await session.WriteJsonFrameSafeAsync(new
                {
                    type = "CONFIRM_COMMAND",
                    confirmedCommand = cmd.Command,
                    success = false,
                    reason = "Laptop state collection failed"
                }, ct);
                return;
            }

            await session.WriteJsonFrameSafeAsync(new
            {
                type = "LAPTOP_STATE",
                batteryLevel = snap.BatteryLevel,
                batteryPercent = snap.BatteryLevel,
                isCharging = snap.IsCharging,
                lockState = snap.LockState,
                wallpaperB64 = snap.WallpaperB64,
                wallpaperHash = snap.WallpaperHash,
                timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            }, ct);

            await session.WriteJsonFrameSafeAsync(new
            {
                type = "CONFIRM_COMMAND",
                confirmedCommand = cmd.Command,
                success = true,
                reason = "OK"
            }, ct);

            return;
        }

        bool executed = HardwareExecutor.ExecuteCommand(cmd.Command, _logger, out int currentVol);
        int currentBri = -1;

        _eventBus.Publish(new TetherEvent
        {
            EventType = TetherEventType.HARDWARE_SYNC_REQUESTED,
            Source = "PacketRouter",
            PayloadJson = JsonSerializer.Serialize(new
            {
                HardwareAction = cmd.Command,
                ExecutedBy = device.DisplayName,
                Success = executed
            })
        });

        if (cmdLower.StartsWith("volume_") || cmdLower.StartsWith("set_volume:") || cmdLower.StartsWith("vol_") ||
            cmdLower.StartsWith("brightness_") || cmdLower.StartsWith("set_brightness:") || cmdLower.StartsWith("bright_") ||
            cmd.Command.Equals("volume_get", StringComparison.OrdinalIgnoreCase) ||
            cmd.Command.Equals("vol_get", StringComparison.OrdinalIgnoreCase) ||
            cmd.Command.Equals("get_volume", StringComparison.OrdinalIgnoreCase) ||
            cmd.Command.Equals("brightness_get", StringComparison.OrdinalIgnoreCase) ||
            cmd.Command.Equals("bright_get", StringComparison.OrdinalIgnoreCase) ||
            cmd.Command.Equals("get_brightness", StringComparison.OrdinalIgnoreCase) ||
            cmd.Command.Equals("laptop_state_get", StringComparison.OrdinalIgnoreCase) ||
            cmd.Command.Equals("get_laptop_state", StringComparison.OrdinalIgnoreCase))
        {
            if (currentVol < 0) currentVol = HardwareExecutor.GetSystemVolumeLevel(_logger);
            currentBri = HardwareExecutor.GetSystemBrightnessLevelInUserSession(_logger);
            bool isMuted = HardwareExecutor.GetSystemMuteInUserSession(_logger);

            var snap = LaptopStateCollector.GetLaptopSnapshot(_logger);
            await session.WriteJsonFrameSafeAsync(new
            {
                type = "HARDWARE_METRICS",
                volumeLevel = currentVol,
                isMuted = isMuted,
                brightnessLevel = currentBri,
                batteryLevel = snap.BatteryLevel,
                batteryPercent = snap.BatteryLevel,
                isCharging = snap.IsCharging,
                lockState = snap.LockState,
                wallpaperB64 = snap.WallpaperB64
            }, ct);
        }

        await session.WriteJsonFrameSafeAsync(new
        {
            type = "CONFIRM_COMMAND",
            requestId = cmd.RequestId,
            confirmedCommand = cmd.Command,
            success = executed,
            reason = executed ? "OK" : "Hardware execution failed",
            volumeLevel = currentVol,
            isMuted = HardwareExecutor.GetSystemMuteInUserSession(_logger),
            brightnessLevel = currentBri
        }, ct);
    }
}
