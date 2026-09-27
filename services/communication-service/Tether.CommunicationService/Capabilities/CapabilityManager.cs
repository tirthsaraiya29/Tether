using System;
using System.Collections.Generic;
using System.Linq;
using Tether.CommunicationService.Devices;
using Tether.Shared.Logging;

namespace Tether.CommunicationService.Capabilities;

public sealed class CapabilityManager
{
    private readonly ITetherLogger _logger;

    public CapabilityManager(ITetherLogger logger)
    {
        _logger = logger;
    }

    public static string? MapCommandToCapability(string command) => command switch
    {
        "shutdown" or "reboot" or "sleep" or "halt" => "POWER_ELEVATED",
        "lock_now" or "panic" or "unlock" or "auth_ok"
            or "reset_pending" or "screen_unlock" => "MEDIA",
        "volume_up" or "volume_down"
            or "brightness_up" or "brightness_down" => "MEDIA",
        "PING" or "PONG" => "MEDIA",
        "cmd" or "powershell" or "powershell7"
            or "wsl" or "bash" => "TERMINAL",
        _ => null
    };

    public bool CanDeviceExecuteCommand(TetherDevice device, string command)
    {
        if (device == null || string.IsNullOrEmpty(command))
            return false;

        string? requiredCap = MapCommandToCapability(command);
        if (requiredCap == null)
        {
            _logger.Warning($"CapabilityManager: Rejected unknown or unmapped command '{command}'.");
            return false;
        }

        bool hasCap = device.Capabilities.Contains(requiredCap, StringComparer.OrdinalIgnoreCase);
        if (!hasCap)
        {
            _logger.Warning($"CapabilityManager: Device '{device.DisplayName}' ({device.Fingerprint}) denied execution of '{command}' (requires {requiredCap}).");
        }

        return hasCap;
    }
}
