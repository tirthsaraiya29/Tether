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
            return;
        }

        _logger.Info($"PacketRouter: Command accepted for '{device.DisplayName}': {cmd.Command} (requestId={cmd.RequestId}).");

        bool executed = HardwareExecutor.ExecuteCommand(cmd.Command, _logger);

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

        await FrameCodec.WriteJsonFrameAsync(stream, new ConfirmCommand { ConfirmedCommand = cmd.Command }, ct);
    }
}
