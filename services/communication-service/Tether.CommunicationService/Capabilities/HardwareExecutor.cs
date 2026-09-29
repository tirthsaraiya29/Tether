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

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSDisconnectSession(IntPtr hServer, uint sessionId, bool bWait);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);

    [DllImport("kernel32.dll", SetLastError = false)]
    private static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool DuplicateTokenEx(
        IntPtr hExistingToken,
        uint dwDesiredAccess,
        IntPtr lpTokenAttributes,
        int ImpersonationLevel,
        int TokenType,
        out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool CreateProcessAsUser(
        IntPtr hToken,
        string? lpApplicationName,
        string? lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

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

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct STARTUPINFO
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    private static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;

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
                    if (!locked)
                    {
                        uint activeSession = WTSGetActiveConsoleSessionId();
                        if (activeSession != 0xFFFFFFFF)
                        {
                            locked = WTSDisconnectSession(WTS_CURRENT_SERVER_HANDLE, activeSession, false);
                        }
                    }
                    logger.Info($"HardwareExecutor: LockWorkStation/Disconnect result = {locked}");
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
                    AdjustBrightness(10, logger);
                    return true;

                case "bright_down":
                case "brightness_down":
                    AdjustBrightness(-10, logger);
                    return true;

                case "launch_browser":
                case "browser":
                    return LaunchInUserSession("cmd.exe /c start https://www.google.com", logger);

                case "launch_task_manager":
                case "taskmgr":
                    return LaunchInUserSession("taskmgr.exe", logger);

                case "launch_explorer":
                case "explorer":
                    return LaunchInUserSession("explorer.exe", logger);

                case "launch_settings":
                case "settings":
                    return LaunchInUserSession("cmd.exe /c start ms-settings:", logger);

                case "powershell":
                case "powershell7":
                    return LaunchInUserSession("powershell.exe", logger);

                case "cmd":
                    return LaunchInUserSession("cmd.exe", logger);

                case "calc":
                    return LaunchInUserSession("calc.exe", logger);

                case "notepad":
                    return LaunchInUserSession("notepad.exe", logger);

                default:
                    logger.Warning($"HardwareExecutor: Unrecognized command '{cmd}'. Trying user session launch...");
                    return LaunchInUserSession(cmd, logger);
            }
        }
        catch (Exception ex)
        {
            logger.Error($"HardwareExecutor: Failed executing '{cmd}': {ex.Message}");
            return false;
        }
    }

    private static bool LaunchInUserSession(string commandLine, ITetherLogger logger)
    {
        uint activeSession = WTSGetActiveConsoleSessionId();
        if (activeSession == 0xFFFFFFFF)
        {
            logger.Warning("HardwareExecutor: No active console session found for launch.");
            return false;
        }

        if (WTSQueryUserToken(activeSession, out IntPtr userToken))
        {
            try
            {
                if (DuplicateTokenEx(userToken, 0x10000000 /* MAXIMUM_ALLOWED */, IntPtr.Zero, 2 /* SecurityImpersonation */, 1 /* TokenPrimary */, out IntPtr primaryToken))
                {
                    try
                    {
                        var si = new STARTUPINFO();
                        si.cb = Marshal.SizeOf(si);
                        si.lpDesktop = @"WinSta0\Default";

                        var pi = new PROCESS_INFORMATION();

                        bool success = CreateProcessAsUser(
                            primaryToken,
                            null,
                            commandLine,
                            IntPtr.Zero,
                            IntPtr.Zero,
                            false,
                            0x00000010 /* CREATE_NEW_CONSOLE */,
                            IntPtr.Zero,
                            null,
                            ref si,
                            out pi);

                        if (success)
                        {
                            logger.Info($"HardwareExecutor: Successfully launched '{commandLine}' in user session {activeSession} (PID {pi.dwProcessId}).");
                            CloseHandle(pi.hProcess);
                            CloseHandle(pi.hThread);
                            return true;
                        }
                        else
                        {
                            int err = Marshal.GetLastWin32Error();
                            logger.Warning($"HardwareExecutor: CreateProcessAsUser failed with error code {err}. Falling back to ShellExecute.");
                        }
                    }
                    finally
                    {
                        CloseHandle(primaryToken);
                    }
                }
            }
            finally
            {
                CloseHandle(userToken);
            }
        }

        try
        {
            Process.Start(new ProcessStartInfo(commandLine) { UseShellExecute = true });
            return true;
        }
        catch (Exception ex)
        {
            logger.Error($"HardwareExecutor: Fallback launch failed for '{commandLine}': {ex.Message}");
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

    private static void AdjustBrightness(int delta, ITetherLogger logger)
    {
        bool ddcSuccess = false;
        try
        {
            IntPtr hMonitor = MonitorFromWindow(IntPtr.Zero, 1);
            PHYSICAL_MONITOR[] monitors = new PHYSICAL_MONITOR[1];
            if (GetPhysicalMonitorsFromHMONITOR(hMonitor, 1, monitors))
            {
                if (GetMonitorBrightness(monitors[0].hPhysicalMonitor, out uint min, out uint current, out uint max))
                {
                    int target = Math.Clamp((int)current + delta, (int)min, (int)max);
                    ddcSuccess = SetMonitorBrightness(monitors[0].hPhysicalMonitor, (uint)target);
                }
                DestroyPhysicalMonitor(monitors[0].hPhysicalMonitor);
            }
        }
        catch { }

        if (!ddcSuccess)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -NonInteractive -Command \"$b = (Get-WmiObject -Namespace root/wmi -Class WmiMonitorBrightness).CurrentBrightness; $target = [math]::Max(0, [math]::Min(100, $b + ({delta}))); (Get-WmiObject -Namespace root/wmi -Class WmiMonitorBrightnessMethods).WmiSetBrightness(1, $target)\"",
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                using var p = Process.Start(psi);
                p?.WaitForExit(2000);
            }
            catch (Exception ex)
            {
                logger.Warning($"WMI brightness adjustment failed: {ex.Message}");
            }
        }
    }
}
