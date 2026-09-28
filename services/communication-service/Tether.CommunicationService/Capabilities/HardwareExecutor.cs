using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Tether.Shared.Logging;

namespace Tether.CommunicationService.Capabilities;

public static class HardwareExecutor
{
    private const byte VK_VOLUME_MUTE = 0xAD;
    private const byte VK_VOLUME_DOWN = 0xAE;
    private const byte VK_VOLUME_UP = 0xAF;
    private const byte VK_MEDIA_NEXT_TRACK = 0xB0;
    private const byte VK_MEDIA_PREV_TRACK = 0xB1;
    private const byte VK_MEDIA_PLAY_PAUSE = 0xCD;

    private const uint KEYEVENTF_KEYUP = 0x0002;

    [DllImport("user32.dll")]
    private static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool LockWorkStation();

    [DllImport("powrprof.dll", SetLastError = true)]
    private static extern bool SetSuspendState(bool hibernate, bool forceCritical, bool disableWakeEvent);

    [DllImport("user32.dll")]
    private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint dwFlags);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool GetPhysicalMonitorsFromHMONITOR(IntPtr hMonitor, uint dwPhysicalMonitorArraySize, [Out] PHYSICAL_MONITOR[] pPhysicalMonitorArray);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyPhysicalMonitor(IntPtr hMonitor);

    [DllImport("dxva2.dll", SetLastError = true)]
    private static extern bool GetMonitorBrightness(IntPtr hMonitor, out uint pdwMinimumBrightness, out uint pdwCurrentBrightness, out uint pdwMaximumBrightness);

    [DllImport("dxva2.dll", SetLastError = true)]
    private static extern bool SetMonitorBrightness(IntPtr hMonitor, uint dwBrightness);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct PHYSICAL_MONITOR
    {
        public IntPtr hPhysicalMonitor;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szPhysicalMonitorDescription;
    }

    public static bool ExecuteCommand(string command, ITetherLogger logger)
    {
        string cmd = command.Trim().ToLowerInvariant();
        logger.Info($"HardwareExecutor: Executing hardware command '{cmd}'...");

        try
        {
            switch (cmd)
            {
                case "lock":
                case "lock_now":
                    bool locked = LockWorkStation();
                    logger.Info($"HardwareExecutor: LockWorkStation result = {locked}");
                    return locked;

                case "sleep":
                case "pwr_sleep":
                    bool slept = SetSuspendState(false, true, false);
                    if (!slept)
                    {
                        Process.Start(new ProcessStartInfo("rundll32.exe", "powrprof.dll,SetSuspendState 0,1,0") { CreateNoWindow = true, UseShellExecute = false });
                    }
                    return true;

                case "shutdown":
                case "pwr_shutdown":
                    Process.Start(new ProcessStartInfo("shutdown.exe", "/s /t 0 /f") { CreateNoWindow = true, UseShellExecute = false });
                    return true;

                case "reboot":
                case "pwr_reboot":
                    Process.Start(new ProcessStartInfo("shutdown.exe", "/r /t 0 /f") { CreateNoWindow = true, UseShellExecute = false });
                    return true;

                case "vol_up":
                case "volume_up":
                    SendKeyPress(VK_VOLUME_UP, 4);
                    return true;

                case "vol_down":
                case "volume_down":
                    SendKeyPress(VK_VOLUME_DOWN, 4);
                    return true;

                case "volume_mute":
                case "mute":
                    SendKeyPress(VK_VOLUME_MUTE, 1);
                    return true;

                case "media_play_pause":
                case "play_pause":
                    SendKeyPress(VK_MEDIA_PLAY_PAUSE, 1);
                    return true;

                case "media_next":
                case "next":
                    SendKeyPress(VK_MEDIA_NEXT_TRACK, 1);
                    return true;

                case "media_prev":
                case "prev":
                    SendKeyPress(VK_MEDIA_PREV_TRACK, 1);
                    return true;

                case "bright_up":
                case "brightness_up":
                    AdjustBrightness(10);
                    return true;

                case "bright_down":
                case "brightness_down":
                    AdjustBrightness(-10);
                    return true;

                case "launch_browser":
                case "browser":
                    Process.Start(new ProcessStartInfo("https://www.google.com") { UseShellExecute = true });
                    return true;

                case "launch_task_manager":
                case "taskmgr":
                    Process.Start(new ProcessStartInfo("taskmgr.exe") { UseShellExecute = true });
                    return true;

                case "launch_explorer":
                case "explorer":
                    Process.Start(new ProcessStartInfo("explorer.exe") { UseShellExecute = true });
                    return true;

                case "launch_settings":
                case "settings":
                    Process.Start(new ProcessStartInfo("ms-settings:") { UseShellExecute = true });
                    return true;

                case "powershell":
                case "powershell7":
                    Process.Start(new ProcessStartInfo("powershell.exe") { UseShellExecute = true });
                    return true;

                case "cmd":
                    Process.Start(new ProcessStartInfo("cmd.exe") { UseShellExecute = true });
                    return true;

                case "calc":
                    Process.Start(new ProcessStartInfo("calc.exe") { UseShellExecute = true });
                    return true;

                case "notepad":
                    Process.Start(new ProcessStartInfo("notepad.exe") { UseShellExecute = true });
                    return true;

                default:
                    logger.Warning($"HardwareExecutor: Unrecognized command '{cmd}'. Trying shell execution...");
                    try
                    {
                        Process.Start(new ProcessStartInfo(cmd) { UseShellExecute = true });
                        return true;
                    }
                    catch (Exception ex)
                    {
                        logger.Warning($"HardwareExecutor: Shell launch failed for '{cmd}': {ex.Message}");
                        return false;
                    }
            }
        }
        catch (Exception ex)
        {
            logger.Error($"HardwareExecutor: Failed executing '{cmd}': {ex.Message}");
            return false;
        }
    }

    private static void SendKeyPress(byte vkCode, int times)
    {
        for (int i = 0; i < times; i++)
        {
            keybd_event(vkCode, 0, 0, UIntPtr.Zero);
            keybd_event(vkCode, 0, KEYEVENTF_KEYUP, UIntPtr.Zero);
        }
    }

    private static void AdjustBrightness(int delta)
    {
        try
        {
            IntPtr hMonitor = MonitorFromWindow(IntPtr.Zero, 1);
            PHYSICAL_MONITOR[] monitors = new PHYSICAL_MONITOR[1];
            if (GetPhysicalMonitorsFromHMONITOR(hMonitor, 1, monitors))
            {
                if (GetMonitorBrightness(monitors[0].hPhysicalMonitor, out uint min, out uint current, out uint max))
                {
                    int target = Math.Clamp((int)current + delta, (int)min, (int)max);
                    SetMonitorBrightness(monitors[0].hPhysicalMonitor, (uint)target);
                }
                DestroyPhysicalMonitor(monitors[0].hPhysicalMonitor);
            }
        }
        catch { }
    }
}
