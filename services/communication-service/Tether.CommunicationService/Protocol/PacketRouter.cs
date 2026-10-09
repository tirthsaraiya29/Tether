using System;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Tether.CommunicationService.Capabilities;
using Tether.CommunicationService.Devices;
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

    public PacketRouter(ITetherLogger logger, CapabilityManager capabilityManager, IEventBus eventBus)
    {
        _logger = logger;
        _capabilityManager = capabilityManager;
        _eventBus = eventBus;
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
                await FrameCodec.WriteJsonFrameAsync(stream, new { type = "PONG", timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() }, ct);
                break;

            case "PONG":
                _logger.Debug($"PacketRouter: Received PONG from '{device.DisplayName}'.");
                session.RecordPongReceived();
                break;

            case "COMMAND_EXECUTE":
                await HandleCommandAsync(doc, session, device, stream, ct);
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
            await FrameCodec.WriteJsonFrameAsync(stream, new
            {
                type = "CONFIRM_COMMAND",
                confirmedCommand = cmd.Command,
                success = false,
                reason = "Capability check failed"
            }, ct);
            return;
        }

        _logger.Info($"PacketRouter: Command accepted for '{device.DisplayName}': {cmd.Command} (requestId={cmd.RequestId}).");

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

        if (cmd.Command.Equals("laptop_state_get", StringComparison.OrdinalIgnoreCase) ||
            cmd.Command.Equals("get_laptop_state", StringComparison.OrdinalIgnoreCase) ||
            cmd.Command.Equals("laptop_state", StringComparison.OrdinalIgnoreCase))
        {
            var snap = LaptopStateCollector.GetLaptopSnapshot(_logger);
            await FrameCodec.WriteJsonFrameAsync(stream, new LaptopStateFrame
            {
                BatteryLevel = snap.BatteryLevel,
                BatteryPercent = snap.BatteryLevel,
                IsCharging = snap.IsCharging,
                LockState = snap.LockState,
                WallpaperB64 = snap.WallpaperB64,
                WallpaperHash = snap.WallpaperHash,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            }, ct);
        }
        else if (cmd.Command.Equals("volume_get", StringComparison.OrdinalIgnoreCase) ||
            cmd.Command.Equals("vol_get", StringComparison.OrdinalIgnoreCase) ||
            cmd.Command.Equals("get_volume", StringComparison.OrdinalIgnoreCase))
        {
            var snap = LaptopStateCollector.GetLaptopSnapshot(_logger);
            await FrameCodec.WriteJsonFrameAsync(stream, new
            {
                type = "HARDWARE_METRICS",
                volumeLevel = currentVol,
                batteryLevel = snap.BatteryLevel,
                batteryPercent = snap.BatteryLevel,
                isCharging = snap.IsCharging,
                lockState = snap.LockState,
                wallpaperB64 = snap.WallpaperB64
            }, ct);
        }

        await FrameCodec.WriteJsonFrameAsync(stream, new
        {
            type = "CONFIRM_COMMAND",
            confirmedCommand = cmd.Command,
            success = executed,
            reason = executed ? "OK" : "Hardware execution failed",
            volumeLevel = currentVol
        }, ct);
    }
}
