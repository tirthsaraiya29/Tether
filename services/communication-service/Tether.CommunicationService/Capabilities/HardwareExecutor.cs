using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Tether.Shared.Logging;

namespace Tether.CommunicationService.Capabilities;

public static class HardwareExecutor
{
    private const byte VK_VOLUME_MUTE = 0xAD;
    private const byte VK_VOLUME_DOWN = 0xAE;
    private const byte VK_VOLUME_UP = 0xAF;

    private const uint KEYEVENTF_KEYUP = 0x0002;

    [DllImport("user32.dll")]
    private static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);

    [DllImport("ole32.dll", SetLastError = true)]
    private static extern int CoInitializeEx(IntPtr pvReserved, uint dwCoInit);

    private const uint COINIT_MULTITHREADED = 0x0;

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

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    [DllImport("powrprof.dll", SetLastError = true)]
    private static extern bool SetSuspendState(bool hibernate, bool forceCritical, bool disableWakeEvent);

    // --- Legacy in-process WASAPI interop -------------------------------------
    // NOTE: The MMDeviceEnumerator CLSID below was previously incorrect
    // (BCDE0382-0378-4A96-8208-3B9268011D0D), which caused REGDB_E_CLASSNOTREG
    // and silently failed every volume operation. The correct CLSID is
    // BCDE0395-E52F-467C-8E3D-C4579291692E (registered by mmdevapi.dll).
    [ComImport]
    [Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")]
    private class MMDeviceEnumerator { }

    [Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IMMDeviceEnumerator
    {
        [PreserveSig] int EnumAudioEndpoints(int dataFlow, int dwStateMask, out object ppDevices);
        [PreserveSig] int GetDefaultAudioEndpoint(int dataFlow, int role, out IMMDevice ppEndpoint);
    }

    [Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IMMDevice
    {
        [PreserveSig] int Activate(ref Guid iid, int dwClsCtx, IntPtr pActivationParams, [MarshalAs(UnmanagedType.IUnknown)] out object ppInterface);
    }

    [Guid("5CDF2C82-841E-4546-9722-0CF74078229A"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IAudioEndpointVolume
    {
        [PreserveSig] int RegisterControlChangeNotify(IntPtr pNotify);
        [PreserveSig] int UnregisterControlChangeNotify(IntPtr pNotify);
        [PreserveSig] int GetChannelCount(out uint pnChannelCount);
        [PreserveSig] int SetMasterVolumeLevel(float fLevelDB, ref Guid pguidEventContext);
        [PreserveSig] int SetMasterVolumeLevelScalar(float fLevel, ref Guid pguidEventContext);
        [PreserveSig] int GetMasterVolumeLevel(out float pfLevelDB);
        [PreserveSig] int GetMasterVolumeLevelScalar(out float pfLevel);
        [PreserveSig] int SetChannelVolumeLevel(uint nChannel, float fLevelDB, ref Guid pguidEventContext);
        [PreserveSig] int SetChannelVolumeLevelScalar(uint nChannel, float fLevel, ref Guid pguidEventContext);
        [PreserveSig] int GetChannelVolumeLevel(uint nChannel, out float pfLevelDB);
        [PreserveSig] int GetChannelVolumeLevelScalar(uint nChannel, out float pfLevel);
        [PreserveSig] int SetMute([MarshalAs(UnmanagedType.Bool)] bool bMute, ref Guid pguidEventContext);
        [PreserveSig] int GetMute([MarshalAs(UnmanagedType.Bool)] out bool pbMute);
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
            if (cmd.StartsWith("volume_set:") || cmd.StartsWith("set_volume:") || cmd.StartsWith("vol_set:"))
            {
                var parts = cmd.Split(':');
                if (parts.Length > 1 && int.TryParse(parts[1], out int targetLevel))
                {
                    int clamped = Math.Clamp(targetLevel, 0, 100);
                    bool ok = RunPowerShellAsUser(BuildSetVolumeScript(clamped), logger);
                    logger.Info($"HardwareExecutor: SetSystemVolumeLevel({clamped}) via user session -> {ok}");
                    return ok;
                }
            }

            switch (cmd)
            {
                case "unlock":
                    return SignalUnlockEvent(@"Global\TetherPhoneAppUnlocked", logger);

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

                // -------- MEDIA: must run inside the interactive user session --------
                case "vol_get":
                case "volume_get":
                case "get_volume":
                    int readVol = GetSystemVolumeLevelInUserSession(logger);
                    if (readVol < 0) readVol = GetSystemVolumeLevel(logger);
                    logger.Info($"HardwareExecutor: Read volume level in user session -> {readVol}");
                    return readVol >= 0;

                case "vol_up":
                case "volume_up":
                    bool upOk = RunPowerShellAsUser(BuildAdjustVolumeScript(+5), logger);
                    logger.Info($"HardwareExecutor: volume_up via user session -> {upOk}");
                    return upOk;

                case "vol_down":
                case "volume_down":
                    bool downOk = RunPowerShellAsUser(BuildAdjustVolumeScript(-5), logger);
                    logger.Info($"HardwareExecutor: volume_down via user session -> {downOk}");
                    return downOk;

                case "volume_mute":
                case "mute":
                    bool muteOk = RunPowerShellAsUser(BuildToggleMuteScript(), logger);
                    logger.Info($"HardwareExecutor: volume_mute via user session -> {muteOk}");
                    return muteOk;

                case "bright_up":
                case "brightness_up":
                    return RunPowerShellAsUser(BuildBrightnessScript(10), logger);

                case "bright_down":
                case "brightness_down":
                    return RunPowerShellAsUser(BuildBrightnessScript(-10), logger);
                // ---------------------------------------------------------------------

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

    // =====================================================================
    //  User-session execution helpers
    // =====================================================================

    public static int GetSystemVolumeLevelInUserSession(ITetherLogger logger)
    {
        try
        {
            string script = BuildGetVolumeScript();
            string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));

            uint activeSession = WTSGetActiveConsoleSessionId();
            if (activeSession == 0xFFFFFFFF)
            {
                logger.Warning("HardwareExecutor: No active console session available for user-session volume read.");
                return -1;
            }

            if (!WTSQueryUserToken(activeSession, out IntPtr userToken))
            {
                logger.Warning($"HardwareExecutor: WTSQueryUserToken failed (err={Marshal.GetLastWin32Error()}).");
                return -1;
            }

            try
            {
                if (!DuplicateTokenEx(userToken, 0x10000000 /* MAXIMUM_ALLOWED */,
                        IntPtr.Zero, 2 /* SecurityImpersonation */, 1 /* TokenPrimary */,
                        out IntPtr primaryToken))
                {
                    logger.Warning("HardwareExecutor: DuplicateTokenEx failed.");
                    return -1;
                }

                try
                {
                    var si = new STARTUPINFO
                    {
                        cb = Marshal.SizeOf<STARTUPINFO>(),
                        lpDesktop = @"WinSta0\Default"
                    };
                    var pi = new PROCESS_INFORMATION();

                    string cmdLine =
                        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass " +
                        "-WindowStyle Hidden -EncodedCommand " + encoded;

                    bool ok = CreateProcessAsUser(
                        primaryToken,
                        null,
                        cmdLine,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        false,
                        0x08000000 /* CREATE_NO_WINDOW */,
                        IntPtr.Zero,
                        null,
                        ref si,
                        out pi);

                    if (ok)
                    {
                        uint waitResult = WaitForSingleObject(pi.hProcess, 5000);
                        int exitCode = -1;
                        if (waitResult == 0 /* WAIT_OBJECT_0 */)
                        {
                            if (GetExitCodeProcess(pi.hProcess, out uint code) && code >= 0 && code <= 100)
                            {
                                exitCode = (int)code;
                            }
                        }
                        CloseHandle(pi.hProcess);
                        CloseHandle(pi.hThread);
                        return exitCode;
                    }

                    logger.Warning($"HardwareExecutor: CreateProcessAsUser (PowerShell Volume Get) failed err={Marshal.GetLastWin32Error()}.");
                    return -1;
                }
                finally { CloseHandle(primaryToken); }
            }
            finally { CloseHandle(userToken); }
        }
        catch (Exception ex)
        {
            logger.Error($"HardwareExecutor: GetSystemVolumeLevelInUserSession exception: {ex.Message}");
            return -1;
        }
    }

    /// <summary>
    /// Spawns powershell.exe inside the active console session using the logged-in
    /// user's token, with the provided script passed as a Base64-encoded command.
    /// This is what fixes Session 0 isolation for media / brightness operations.
    /// Waits up to 5s for exit and returns false on non-zero exit code so script
    /// failures surface in the log instead of silently returning true.
    /// </summary>
    private static bool RunPowerShellAsUser(string psScript, ITetherLogger logger)
    {
        try
        {
            // PowerShell's -EncodedCommand expects Base64 of UTF-16LE.
            string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(psScript));

            uint activeSession = WTSGetActiveConsoleSessionId();
            if (activeSession == 0xFFFFFFFF)
            {
                logger.Warning("HardwareExecutor: No active console session available for user-session execution.");
                return false;
            }

            if (!WTSQueryUserToken(activeSession, out IntPtr userToken))
            {
                logger.Warning($"HardwareExecutor: WTSQueryUserToken failed (err={Marshal.GetLastWin32Error()}).");
                return false;
            }

            try
            {
                if (!DuplicateTokenEx(userToken, 0x10000000 /* MAXIMUM_ALLOWED */,
                        IntPtr.Zero, 2 /* SecurityImpersonation */, 1 /* TokenPrimary */,
                        out IntPtr primaryToken))
                {
                    logger.Warning("HardwareExecutor: DuplicateTokenEx failed.");
                    return false;
                }

                try
                {
                    var si = new STARTUPINFO
                    {
                        cb = Marshal.SizeOf<STARTUPINFO>(),
                        lpDesktop = @"WinSta0\Default"
                    };
                    var pi = new PROCESS_INFORMATION();

                    string cmdLine =
                        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass " +
                        "-WindowStyle Hidden -EncodedCommand " + encoded;

                    bool ok = CreateProcessAsUser(
                        primaryToken,
                        null,
                        cmdLine,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        false,
                        0x08000000 /* CREATE_NO_WINDOW */,
                        IntPtr.Zero,
                        null,
                        ref si,
                        out pi);

                    if (!ok)
                    {
                        logger.Warning($"HardwareExecutor: CreateProcessAsUser (PowerShell) failed err={Marshal.GetLastWin32Error()}.");
                        return false;
                    }

                    uint waitResult = WaitForSingleObject(pi.hProcess, 5000);
                    bool success = true;

                    if (waitResult == 0 /* WAIT_OBJECT_0 */)
                    {
                        if (GetExitCodeProcess(pi.hProcess, out uint exitCode))
                        {
                            if (exitCode != 0)
                            {
                                logger.Warning($"HardwareExecutor: user-session PowerShell script exited with code 0x{exitCode:X}.");
                                success = false;
                            }
                        }
                    }
                    else
                    {
                        logger.Warning("HardwareExecutor: user-session PowerShell script did not exit within 5000ms; continuing optimistically.");
                    }

                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                    return success;
                }
                finally { CloseHandle(primaryToken); }
            }
            finally { CloseHandle(userToken); }
        }
        catch (Exception ex)
        {
            logger.Error($"HardwareExecutor: RunPowerShellAsUser exception: {ex.Message}");
            return false;
        }
    }

    // =====================================================================
    //  PowerShell script builders
    // =====================================================================

    /// <summary>
    /// Shared inline C# source declaring the WASAPI interop surface with the
    /// CORRECT CLSID for MMDeviceEnumerator (BCDE0395-E52F-467C-8E3D-C4579291692E).
    /// The previous code used a fabricated GUID which produced REGDB_E_CLASSNOTREG
    /// and silently failed every volume operation.
    /// </summary>
    private static readonly string WasapiInteropSource = """
using System;
using System.Runtime.InteropServices;

[Guid("5CDF2C82-841E-4546-9722-0CF74078229A"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IAudioEndpointVolume {
    int RegisterControlChangeNotify(IntPtr pNotify);
    int UnregisterControlChangeNotify(IntPtr pNotify);
    int GetChannelCount(out uint pnChannelCount);
    int SetMasterVolumeLevel(float fLevelDB, ref Guid pguidEventContext);
    int SetMasterVolumeLevelScalar(float fLevel, ref Guid pguidEventContext);
    int GetMasterVolumeLevel(out float pfLevelDB);
    int GetMasterVolumeLevelScalar(out float pfLevel);
    int SetChannelVolumeLevel(uint nChannel, float fLevelDB, ref Guid pguidEventContext);
    int SetChannelVolumeLevelScalar(uint nChannel, float fLevel, ref Guid pguidEventContext);
    int GetChannelVolumeLevel(uint nChannel, out float pfLevelDB);
    int GetChannelVolumeLevelScalar(uint nChannel, out float pfLevel);
    int SetMute([MarshalAs(UnmanagedType.Bool)] bool bMute, ref Guid pguidEventContext);
    int GetMute([MarshalAs(UnmanagedType.Bool)] out bool pbMute);
}

[Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IMMDevice {
    int Activate(ref Guid iid, int dwClsCtx, IntPtr pActivationParams, [MarshalAs(UnmanagedType.IUnknown)] out object ppInterface);
}

[Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IMMDeviceEnumerator {
    int EnumAudioEndpoints(int dataFlow, int dwStateMask, out object ppDevices);
    int GetDefaultAudioEndpoint(int dataFlow, int role, out IMMDevice ppEndpoint);
}

[ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")]
class MMDeviceEnumeratorComObject { }
""";

    private static string BuildSetVolumeScript(int level)
    {
        return $$"""
$src = @'
{{WasapiInteropSource}}

public static class TetherVol {
    public static int Set(int level) {
        var enumerator = (IMMDeviceEnumerator)(new MMDeviceEnumeratorComObject());
        IMMDevice dev;
        int hr = enumerator.GetDefaultAudioEndpoint(0, 0, out dev);
        if (hr != 0 || dev == null) throw new Exception("GetDefaultAudioEndpoint hr=" + hr);
        Guid iid = typeof(IAudioEndpointVolume).GUID;
        object o;
        hr = dev.Activate(ref iid, 1, IntPtr.Zero, out o);
        if (hr != 0 || o == null) throw new Exception("Activate hr=" + hr);
        var vol = (IAudioEndpointVolume)o;
        Guid empty = Guid.Empty;
        float scalar = Math.Max(0f, Math.Min(1f, level / 100f));
        hr = vol.SetMasterVolumeLevelScalar(scalar, ref empty);
        if (hr != 0) throw new Exception("SetMasterVolumeLevelScalar hr=" + hr);
        return level;
    }
}
'@
try {
    Add-Type -TypeDefinition $src -Language CSharp -ErrorAction Stop | Out-Null
    $v = [TetherVol]::Set({{level}})
    Write-Output "volume set to $v"
    exit 0
} catch {
    Write-Error $_
    exit 1
}
""";
    }

    private static string BuildAdjustVolumeScript(int delta)
    {
        return $$"""
$src = @'
{{WasapiInteropSource}}

public static class TetherVolAdjust {
    public static int Adjust(int delta) {
        var enumerator = (IMMDeviceEnumerator)(new MMDeviceEnumeratorComObject());
        IMMDevice dev;
        int hr = enumerator.GetDefaultAudioEndpoint(0, 0, out dev);
        if (hr != 0 || dev == null) throw new Exception("GetDefaultAudioEndpoint hr=" + hr);
        Guid iid = typeof(IAudioEndpointVolume).GUID;
        object o;
        hr = dev.Activate(ref iid, 1, IntPtr.Zero, out o);
        if (hr != 0 || o == null) throw new Exception("Activate hr=" + hr);
        var vol = (IAudioEndpointVolume)o;
        float cur = 0f;
        hr = vol.GetMasterVolumeLevelScalar(out cur);
        if (hr != 0) throw new Exception("GetMasterVolumeLevelScalar hr=" + hr);
        int current = (int)Math.Round(cur * 100f);
        int target = Math.Max(0, Math.Min(100, current + delta));
        Guid empty = Guid.Empty;
        hr = vol.SetMasterVolumeLevelScalar(target / 100f, ref empty);
        if (hr != 0) throw new Exception("SetMasterVolumeLevelScalar hr=" + hr);
        return target;
    }
}
'@
try {
    Add-Type -TypeDefinition $src -Language CSharp -ErrorAction Stop | Out-Null
    $v = [TetherVolAdjust]::Adjust({{delta}})
    Write-Output "volume adjusted to $v"
    exit 0
} catch {
    Write-Error $_
    exit 1
}
""";
    }

    private static string BuildToggleMuteScript()
    {
        return $$"""
$src = @'
{{WasapiInteropSource}}

public static class TetherMute {
    public static bool Toggle() {
        var enumerator = (IMMDeviceEnumerator)(new MMDeviceEnumeratorComObject());
        IMMDevice dev;
        int hr = enumerator.GetDefaultAudioEndpoint(0, 0, out dev);
        if (hr != 0 || dev == null) throw new Exception("GetDefaultAudioEndpoint hr=" + hr);
        Guid iid = typeof(IAudioEndpointVolume).GUID;
        object o;
        hr = dev.Activate(ref iid, 1, IntPtr.Zero, out o);
        if (hr != 0 || o == null) throw new Exception("Activate hr=" + hr);
        var vol = (IAudioEndpointVolume)o;
        bool muted = false;
        hr = vol.GetMute(out muted);
        if (hr != 0) throw new Exception("GetMute hr=" + hr);
        Guid empty = Guid.Empty;
        hr = vol.SetMute(!muted, ref empty);
        if (hr != 0) throw new Exception("SetMute hr=" + hr);
        return !muted;
    }
}
'@
try {
    Add-Type -TypeDefinition $src -Language CSharp -ErrorAction Stop | Out-Null
    $m = [TetherMute]::Toggle()
    Write-Output "mute toggled to $m"
    exit 0
} catch {
    Write-Error $_
    exit 1
}
""";
    }

    private static string BuildGetVolumeScript()
    {
        return $$"""
$src = @'
{{WasapiInteropSource}}

public static class TetherVolGet {
    public static int Get() {
        var enumerator = (IMMDeviceEnumerator)(new MMDeviceEnumeratorComObject());
        IMMDevice dev;
        int hr = enumerator.GetDefaultAudioEndpoint(0, 0, out dev);
        if (hr != 0 || dev == null) return -1;
        Guid iid = typeof(IAudioEndpointVolume).GUID;
        object o;
        hr = dev.Activate(ref iid, 1, IntPtr.Zero, out o);
        if (hr != 0 || o == null) return -1;
        var vol = (IAudioEndpointVolume)o;
        float level = 0f;
        hr = vol.GetMasterVolumeLevelScalar(out level);
        if (hr != 0) return -1;
        return (int)Math.Round(level * 100f);
    }
}
'@
try {
    Add-Type -TypeDefinition $src -Language CSharp -ErrorAction Stop | Out-Null
    $v = [TetherVolGet]::Get()
    if ($v -ge 0) { exit $v } else { exit 255 }
} catch {
    Write-Error $_
    exit 255
}
""";
    }

    private static string BuildBrightnessScript(int delta)
    {
        return $$"""
$delta = {{delta}}
try {
    $b = (Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorBrightness -ErrorAction Stop).CurrentBrightness
    $target = [Math]::Max(0, [Math]::Min(100, $b + $delta))
    (Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorBrightnessMethods -ErrorAction Stop).WmiSetBrightness(1, $target) | Out-Null
    exit 0
} catch {
    Write-Error $_
    exit 1
}
""";
    }

    // =====================================================================
    //  Existing helpers (unlock / launch / legacy WASAPI surface)
    // =====================================================================

    private static bool SignalUnlockEvent(string eventName, ITetherLogger logger)
    {
        try
        {
            using var evt = EventWaitHandle.OpenExisting(eventName);
            bool setOk = evt.Set();
            logger.Info($"HardwareExecutor: Signaled unlock event '{eventName}', setOk={setOk}");
            return setOk;
        }
        catch (Exception ex)
        {
            try
            {
                using var evt = new EventWaitHandle(false, EventResetMode.AutoReset, eventName, out bool createdNew);
                bool setOk = evt.Set();
                logger.Info($"HardwareExecutor: Created & Signaled unlock event '{eventName}', createdNew={createdNew}, setOk={setOk}");
                return setOk;
            }
            catch (Exception createEx)
            {
                logger.Error($"HardwareExecutor: Failed to signal unlock event '{eventName}': {ex.Message} / {createEx.Message}");
                return false;
            }
        }
    }

    // NOTE: Legacy in-process helpers. They still operate inside the service's own
    // session (Session 0), so they will not affect the interactive user's default
    // audio endpoint. Kept for backward compatibility with external callers only.
    public static int GetSystemVolumeLevel(ITetherLogger? logger = null)
    {
        try
        {
            CoInitializeEx(IntPtr.Zero, COINIT_MULTITHREADED);
            var enumerator = (IMMDeviceEnumerator)new MMDeviceEnumerator();
            int hr = enumerator.GetDefaultAudioEndpoint(0, 0, out IMMDevice device);
            if (hr != 0 || device == null) return -1;
            Guid iid = new Guid("5CDF2C82-841E-4546-9722-0CF74078229A");
            hr = device.Activate(ref iid, 1, IntPtr.Zero, out object comInterface);
            if (hr != 0 || comInterface == null) return -1;
            var vol = (IAudioEndpointVolume)comInterface;
            vol.GetMasterVolumeLevelScalar(out float level);
            Marshal.ReleaseComObject(vol);
            Marshal.ReleaseComObject(device);
            Marshal.ReleaseComObject(enumerator);
            return (int)Math.Round(level * 100.0f);
        }
        catch { return -1; }
    }

    public static bool SetSystemVolumeLevel(int levelPercent, ITetherLogger? logger = null)
    {
        try
        {
            CoInitializeEx(IntPtr.Zero, COINIT_MULTITHREADED);
            float scalar = Math.Clamp(levelPercent / 100.0f, 0.0f, 1.0f);
            var enumerator = (IMMDeviceEnumerator)new MMDeviceEnumerator();
            int hr = enumerator.GetDefaultAudioEndpoint(0, 0, out IMMDevice device);
            if (hr != 0 || device == null) return false;
            Guid iid = new Guid("5CDF2C82-841E-4546-9722-0CF74078229A");
            hr = device.Activate(ref iid, 1, IntPtr.Zero, out object comInterface);
            if (hr != 0 || comInterface == null) return false;
            var vol = (IAudioEndpointVolume)comInterface;
            Guid empty = Guid.Empty;
            vol.SetMasterVolumeLevelScalar(scalar, ref empty);
            Marshal.ReleaseComObject(vol);
            Marshal.ReleaseComObject(device);
            Marshal.ReleaseComObject(enumerator);
            return true;
        }
        catch { return false; }
    }

    public static bool AdjustSystemVolume(int deltaPercent, ITetherLogger? logger = null)
    {
        int current = GetSystemVolumeLevel(logger);
        if (current < 0) current = 50;
        return SetSystemVolumeLevel(current + deltaPercent, logger);
    }

    public static bool ToggleSystemMute(ITetherLogger? logger = null)
    {
        try
        {
            CoInitializeEx(IntPtr.Zero, COINIT_MULTITHREADED);
            var enumerator = (IMMDeviceEnumerator)new MMDeviceEnumerator();
            enumerator.GetDefaultAudioEndpoint(0, 0, out IMMDevice device);
            Guid iid = new Guid("5CDF2C82-841E-4546-9722-0CF74078229A");
            device.Activate(ref iid, 1, IntPtr.Zero, out object comInterface);
            var vol = (IAudioEndpointVolume)comInterface;
            vol.GetMute(out bool isMuted);
            Guid empty = Guid.Empty;
            vol.SetMute(!isMuted, ref empty);
            Marshal.ReleaseComObject(vol);
            Marshal.ReleaseComObject(device);
            Marshal.ReleaseComObject(enumerator);
            return true;
        }
        catch { return false; }
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
                if (DuplicateTokenEx(userToken, 0x10000000, IntPtr.Zero, 2, 1, out IntPtr primaryToken))
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
}