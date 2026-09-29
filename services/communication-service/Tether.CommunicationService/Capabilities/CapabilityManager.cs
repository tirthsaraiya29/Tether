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

    public static string? MapCommandToCapability(string command)
    {
        string cmd = command.Trim().ToLowerInvariant();
        if (cmd.StartsWith("volume_") || cmd.StartsWith("set_volume") || cmd.StartsWith("vol_"))
            return "MEDIA";

        return cmd switch
        {
            "shutdown" or "reboot" or "sleep" or "halt"
                or "pwr_shutdown" or "pwr_reboot" or "pwr_sleep" => "POWER_ELEVATED",

            "lock_now" or "panic" or "unlock" or "auth_ok"
                or "reset_pending" or "screen_unlock" => "MEDIA",

            "volume_up" or "volume_down" or "vol_up" or "vol_down"
                or "volume_mute" or "mute" or "brightness_up" or "brightness_down"
                or "bright_up" or "bright_down" or "media_play_pause" or "play_pause"
                or "media_next" or "next" or "media_prev" or "prev" => "MEDIA",

            "launch_browser" or "launch_task_manager" or "launch_explorer" or "launch_settings"
                or "browser" or "taskmgr" or "explorer" or "settings"
                or "calc" or "notepad" or "cmd" or "powershell" or "powershell7"
                or "wsl" or "bash" => "TERMINAL",

            "PING" or "PONG" => "MEDIA",

            _ => "MEDIA"
        };
    }

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
