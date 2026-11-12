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



        if (cmd.StartsWith("volume_") || cmd.StartsWith("set_volume") || cmd.StartsWith("vol_") ||

            cmd.StartsWith("brightness_") || cmd.StartsWith("set_brightness") || cmd.StartsWith("bright_") ||

            cmd.StartsWith("audio_") || cmd.StartsWith("mic_") || cmd.StartsWith("media_"))

        {

            return "MEDIA";

        }



        if (cmd.StartsWith("terminal_") || cmd is "cmd" or "powershell" or "powershell7" or "wsl" or "bash")

        {

            return "TERMINAL";

        }



        if (cmd.StartsWith("clipboard_") || cmd is "copy" or "paste" or "clipboard")

        {

            return "CLIPBOARD";

        }



        if (cmd.StartsWith("notification_"))

        {

            return "NOTIFICATIONS";

        }



        if (cmd.StartsWith("admin_") || cmd.StartsWith("service_") || cmd.StartsWith("power_plan") ||

            cmd is "battery_health_get" or "printers_get" or "usb_devices_get" or "services_get" or "updates_check")

        {

            return "WINDOWS_ADMIN";

        }



        if (cmd.StartsWith("launch_") ||

            cmd is "browser" or "taskmgr" or "explorer" or "settings" or "calc" or "notepad")

        {

            return "APP_LAUNCH";

        }



        if (cmd.StartsWith("app_"))

        {

            return "APP_MANAGEMENT";

        }



        if (cmd.StartsWith("workflow_"))

        {

            return "AUTOMATION";

        }



        return cmd switch

        {

            "shutdown" or "reboot" or "sleep" or "halt"

                or "pwr_shutdown" or "pwr_reboot" or "pwr_sleep"

                or "unlock" or "auth_ok" => "POWER_ELEVATED",



            "lock_now" or "panic"

                or "reset_pending" or "laptop_state_get" or "get_laptop_state" or "laptop_state" => "MEDIA",



            "volume_up" or "volume_down" or "vol_up" or "vol_down"

                or "volume_mute" or "mute" or "volume_mute_on" or "mute_on" or "volume_mute_off" or "mute_off" or "unmute" or "brightness_up" or "brightness_down"

                or "bright_up" or "bright_down" => "MEDIA",



            "launch_browser" or "launch_task_manager" or "launch_explorer" or "launch_settings"

                or "launch_calc" or "launch_notepad"

                or "browser" or "taskmgr" or "explorer" or "settings"

                or "calc" or "notepad" => "APP_LAUNCH",



            "ping" or "pong" or "PING" or "PONG" => "MEDIA",



            _ => null

        };

    }



    public bool HasCapability(TetherDevice device, string requiredCap)

    {

        if (device == null || string.IsNullOrEmpty(requiredCap))

            return false;



        var caps = (device.Capabilities == null || device.Capabilities.Count == 0)

            ? (device.TrustState == DeviceTrustState.Paired ? DefaultCapabilities.ToList() : new List<string>())

            : device.Capabilities;



        if (caps.Contains("*"))

            return true;



        if (caps.Contains(requiredCap, StringComparer.OrdinalIgnoreCase))

            return true;



        if (requiredCap.Equals("APP_LAUNCH", StringComparison.OrdinalIgnoreCase) &&

            caps.Contains("APP_MANAGEMENT", StringComparer.OrdinalIgnoreCase))

            return true;



        if (requiredCap.Equals("POWER_ELEVATED", StringComparison.OrdinalIgnoreCase) &&

            (caps.Contains("SYSTEM_UNLOCK", StringComparer.OrdinalIgnoreCase) ||

             caps.Contains("SYSTEM_CONTROL", StringComparer.OrdinalIgnoreCase)))

            return true;



        return false;

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



        bool hasCap = HasCapability(device, requiredCap);



        if (!hasCap)

        {

            _logger.Warning($"CapabilityManager: Device '{device.DisplayName}' ({device.Fingerprint}) denied execution of '{command}' (requires {requiredCap}).");

        }



        return hasCap;

    }



    public static IEnumerable<string> DefaultCapabilities =>

        new[] { "MEDIA", "APP_LAUNCH", "FILES" };



    public static IEnumerable<string> ElevatedCapabilities =>

        new[] { "MEDIA", "APP_LAUNCH", "FILES", "POWER_ELEVATED", "WINDOWS_ADMIN", "APP_MANAGEMENT", "AUTOMATION", "TERMINAL", "CLIPBOARD", "NOTIFICATIONS" };

}

