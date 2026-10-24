using System;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Tether.CommunicationService.Capabilities;
using Tether.CommunicationService.Devices;
using Tether.CommunicationService.FileTransfer;
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

    public PacketRouter(ITetherLogger logger, CapabilityManager capabilityManager, IEventBus eventBus, TokenStore tokenStore)
    {
        _logger = logger;
        _capabilityManager = capabilityManager;
        _eventBus = eventBus;
        _tokenStore = tokenStore;
    }

    public async Task RouteFrameAsync(JsonDocument doc, TetherSession session, TetherDevice device, Stream stream, CancellationToken ct)
    {
        string type;
        try { type = doc.RootElement.GetProperty("type").GetString() ?? ""; }
        catch { return; }

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
                _logger.Info($"PacketRouter: Received FILE_TRANSFER_TOKEN_REQUEST from '{device.DisplayName}'. Generating token.");
                var token = _tokenStore.GenerateToken(TimeSpan.FromMinutes(60)); // 1 hour token
                await session.WriteJsonFrameSafeAsync(new { type = "FILE_TRANSFER_TOKEN_RESPONSE", token = token, validForMinutes = 60 }, ct);
                break;

            case "FS_LIST_RESULT":
            case "FS_DOWNLOAD_RESULT":
            case "FS_UPLOAD_RESULT":
            case "FS_TRANSFER_STATUS":
                FileTransferServer.HandleRemoteResponse(type, doc.RootElement.GetRawText());
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

        _eventBus.Publish(new TetherEvent
        {
            EventType = TetherEventType.TRUST_DEGRADED,
            Source = "PacketRouter",
            PayloadJson = JsonSerializer.Serialize(new
            {
                HardwareAction = cmd.Command,
                ExecutedBy = device.DisplayName,
                Success = executed
            })
        });

        if (currentVol < 0) currentVol = HardwareExecutor.GetSystemVolumeLevel(_logger);
        int currentBri = HardwareExecutor.GetSystemBrightnessLevelInUserSession(_logger);

        if (cmdLower.StartsWith("volume_") || cmdLower.StartsWith("set_volume:") || cmdLower.StartsWith("vol_") ||
            cmdLower.StartsWith("brightness_") || cmdLower.StartsWith("set_brightness:") || cmdLower.StartsWith("bright_"))
        {
            var snap = LaptopStateCollector.GetLaptopSnapshot(_logger);
            await session.WriteJsonFrameSafeAsync(new
            {
                type = "HARDWARE_METRICS",
                volumeLevel = currentVol,
                brightnessLevel = currentBri,
                batteryLevel = snap.BatteryLevel,
                batteryPercent = snap.BatteryLevel,
                isCharging = snap.IsCharging,
                lockState = snap.LockState,
                wallpaperB64 = snap.WallpaperB64
            }, ct);
        }
        else if (cmd.Command.Equals("volume_get", StringComparison.OrdinalIgnoreCase) ||
            cmd.Command.Equals("vol_get", StringComparison.OrdinalIgnoreCase) ||
            cmd.Command.Equals("get_volume", StringComparison.OrdinalIgnoreCase) ||
            cmd.Command.Equals("brightness_get", StringComparison.OrdinalIgnoreCase) ||
            cmd.Command.Equals("bright_get", StringComparison.OrdinalIgnoreCase) ||
            cmd.Command.Equals("get_brightness", StringComparison.OrdinalIgnoreCase))
        {
            var snap = LaptopStateCollector.GetLaptopSnapshot(_logger);
            await session.WriteJsonFrameSafeAsync(new
            {
                type = "HARDWARE_METRICS",
                volumeLevel = currentVol,
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
            confirmedCommand = cmd.Command,
            success = executed,
            reason = executed ? "OK" : "Hardware execution failed",
            volumeLevel = currentVol,
            brightnessLevel = currentBri
        }, ct);
    }
}
