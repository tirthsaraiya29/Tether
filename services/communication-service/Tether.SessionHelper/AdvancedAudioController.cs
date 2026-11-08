using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Tether.SessionHelper;

internal static class AdvancedAudioController
{
    [ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")]
    private class MMDeviceEnumerator { }

    [Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IMMDeviceEnumerator
    {
        [PreserveSig] int EnumAudioEndpoints(int dataFlow, int dwStateMask, out IMMDeviceCollection ppDevices);
        [PreserveSig] int GetDefaultAudioEndpoint(int dataFlow, int role, out IMMDevice ppEndpoint);
    }

    [Guid("0BD7A1BE-7A1A-44DB-8397-CC5392387B5E"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IMMDeviceCollection
    {
        [PreserveSig] int GetCount(out int pcDevices);
        [PreserveSig] int Item(int nDevice, out IMMDevice ppDevice);
    }

    [Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IMMDevice
    {
        [PreserveSig] int Activate(ref Guid iid, int dwClsCtx, IntPtr pActivationParams, [MarshalAs(UnmanagedType.IUnknown)] out object ppInterface);
        [PreserveSig] int OpenPropertyStore(int stgmAccess, out IPropertyStore ppProperties);
        [PreserveSig] int GetId([MarshalAs(UnmanagedType.LPWStr)] out string ppstrId);
    }

    [Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IPropertyStore
    {
        [PreserveSig] int GetCount(out int cProps);
        [PreserveSig] int GetAt(int iProp, out PROPERTYKEY pkey);
        [PreserveSig] int GetValue(ref PROPERTYKEY key, out PROPVARIANT pv);
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct PROPERTYKEY
    {
        public Guid fmtid;
        public uint pid;
    }

    [StructLayout(LayoutKind.Explicit)]
    private struct PROPVARIANT
    {
        [FieldOffset(0)] public ushort vt;
        [FieldOffset(8)] public IntPtr pwszVal;
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

    [Guid("77AA99A0-1BD6-484F-BC23-44C9509B3988"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IAudioSessionManager2
    {
        [PreserveSig] int GetSessionEnumerator(out IAudioSessionEnumerator SessionEnum);
    }

    [Guid("E2F5EE11-070A-461B-A510-49FC85EF8753"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IAudioSessionEnumerator
    {
        [PreserveSig] int GetCount(out int SessionCount);
        [PreserveSig] int GetSession(int SessionIndex, out object Session);
    }

    [Guid("BFB7FF88-7239-4FC9-8FA2-07C950BE9C6D"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IAudioSessionControl2
    {
        [PreserveSig] int GetState(out int pRetVal);
        [PreserveSig] int GetDisplayName([MarshalAs(UnmanagedType.LPWStr)] out string pRetVal);
        [PreserveSig] int SetDisplayName([MarshalAs(UnmanagedType.LPWStr)] string Value, ref Guid EventContext);
        [PreserveSig] int GetIconPath([MarshalAs(UnmanagedType.LPWStr)] out string pRetVal);
        [PreserveSig] int SetIconPath([MarshalAs(UnmanagedType.LPWStr)] string Value, ref Guid EventContext);
        [PreserveSig] int GetGroupingParam(out Guid pRetVal);
        [PreserveSig] int SetGroupingParam(ref Guid Override, ref Guid EventContext);
        [PreserveSig] int RegisterAudioSessionNotification(IntPtr NewNotifications);
        [PreserveSig] int UnregisterAudioSessionNotification(IntPtr NewNotifications);
        [PreserveSig] int GetSessionIdentifier([MarshalAs(UnmanagedType.LPWStr)] out string pRetVal);
        [PreserveSig] int GetSessionInstanceIdentifier([MarshalAs(UnmanagedType.LPWStr)] out string pRetVal);
        [PreserveSig] int GetProcessId(out uint pRetVal);
        [PreserveSig] int IsSystemSoundsSession();
    }

    [Guid("87CE5498-68D6-44E5-AC9B-4AA64C8020C0"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface ISimpleAudioVolume
    {
        [PreserveSig] int SetMasterVolume(float fLevel, ref Guid EventContext);
        [PreserveSig] int GetMasterVolume(out float pfLevel);
        [PreserveSig] int SetMute([MarshalAs(UnmanagedType.Bool)] bool bMute, ref Guid EventContext);
        [PreserveSig] int GetMute([MarshalAs(UnmanagedType.Bool)] out bool pbMute);
    }

    [ComImport, Guid("87042DA8-A749-4C3C-B948-F615BF62C155")]
    private class PolicyConfig { }

    [Guid("F8679F50-850A-41CF-9C72-430F290290C8"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IPolicyConfig
    {
        [PreserveSig] int GetMixFormat(string pszDeviceName, IntPtr ppFormat);
        [PreserveSig] int GetDeviceFormat(string pszDeviceName, int bDefault, IntPtr ppFormat);
        [PreserveSig] int ResetDeviceFormat(string pszDeviceName);
        [PreserveSig] int SetDeviceFormat(string pszDeviceName, IntPtr pEndpointFormat, IntPtr mixFormat);
        [PreserveSig] int GetProcessingPeriod(string pszDeviceName, int bDefault, IntPtr pmftDefaultPeriod, IntPtr pmftMinimumPeriod);
        [PreserveSig] int SetProcessingPeriod(string pszDeviceName, IntPtr pmftPeriod);
        [PreserveSig] int GetShareMode(string pszDeviceName, IntPtr pMode);
        [PreserveSig] int SetShareMode(string pszDeviceName, IntPtr mode);
        [PreserveSig] int GetPropertyValue(string pszDeviceName, ref PROPERTYKEY pKey, out PROPVARIANT pv);
        [PreserveSig] int SetPropertyValue(string pszDeviceName, ref PROPERTYKEY pKey, ref PROPVARIANT pv);
        [PreserveSig] int SetDefaultEndpoint([MarshalAs(UnmanagedType.LPWStr)] string pszDeviceName, int role);
        [PreserveSig] int SetEndpointVisibility(string pszDeviceName, int bVisible);
    }

    private static readonly PROPERTYKEY PKEY_Device_FriendlyName = new()
    {
        fmtid = new Guid("A45C254E-DF1C-4EFD-8020-67D146A850E0"),
        pid = 14
    };

    public static List<AppAudioSession> GetAppAudioSessions()
    {
        var result = new List<AppAudioSession>();
        var enumerator = (IMMDeviceEnumerator)(new MMDeviceEnumerator());
        try
        {
            int hr = enumerator.GetDefaultAudioEndpoint(0 /* eRender */, 0 /* eConsole */, out IMMDevice dev);
            if (hr != 0 || dev is null) return result;

            try
            {
                Guid iid = typeof(IAudioSessionManager2).GUID;
                hr = dev.Activate(ref iid, 1, IntPtr.Zero, out object o);
                if (hr != 0 || o is null) return result;

                var mgr = (IAudioSessionManager2)o;
                try
                {
                    hr = mgr.GetSessionEnumerator(out IAudioSessionEnumerator sessionEnum);
                    if (hr != 0 || sessionEnum is null) return result;

                    try
                    {
                        sessionEnum.GetCount(out int count);
                        for (int i = 0; i < count; i++)
                        {
                            hr = sessionEnum.GetSession(i, out object sessionObj);
                            if (hr != 0 || sessionObj is null) continue;

                            try
                            {
                                if (sessionObj is IAudioSessionControl2 ctl2 && sessionObj is ISimpleAudioVolume vol)
                                {
                                    ctl2.GetProcessId(out uint pid);
                                    if (pid == 0) continue; // Skip idle or system audio master

                                    string procName = "Unknown";
                                    try
                                    {
                                        using var proc = Process.GetProcessById((int)pid);
                                        procName = proc.ProcessName;
                                    }
                                    catch { }

                                    vol.GetMasterVolume(out float volScalar);
                                    vol.GetMute(out bool isMuted);

                                    result.Add(new AppAudioSession
                                    {
                                        ProcessId = (int)pid,
                                        ProcessName = procName,
                                        VolumePercent = (int)Math.Round(volScalar * 100f),
                                        IsMuted = isMuted
                                    });
                                }
                            }
                            finally
                            {
                                Marshal.ReleaseComObject(sessionObj);
                            }
                        }
                    }
                    finally { Marshal.ReleaseComObject(sessionEnum); }
                }
                finally { Marshal.ReleaseComObject(mgr); }
            }
            finally { Marshal.ReleaseComObject(dev); }
        }
        catch { }
        finally { Marshal.ReleaseComObject(enumerator); }

        return result;
    }

    public static bool SetAppVolume(int targetPid, int percent)
    {
        float scalar = Math.Clamp(percent / 100f, 0f, 1f);
        return ModifyAppAudio(targetPid, vol =>
        {
            Guid empty = Guid.Empty;
            vol.SetMasterVolume(scalar, ref empty);
        });
    }

    public static bool SetAppMute(int targetPid, bool isMuted)
    {
        return ModifyAppAudio(targetPid, vol =>
        {
            Guid empty = Guid.Empty;
            vol.SetMute(isMuted, ref empty);
        });
    }

    private static bool ModifyAppAudio(int targetPid, Action<ISimpleAudioVolume> action)
    {
        var enumerator = (IMMDeviceEnumerator)(new MMDeviceEnumerator());
        try
        {
            int hr = enumerator.GetDefaultAudioEndpoint(0, 0, out IMMDevice dev);
            if (hr != 0 || dev is null) return false;

            try
            {
                Guid iid = typeof(IAudioSessionManager2).GUID;
                hr = dev.Activate(ref iid, 1, IntPtr.Zero, out object o);
                if (hr != 0 || o is null) return false;

                var mgr = (IAudioSessionManager2)o;
                try
                {
                    hr = mgr.GetSessionEnumerator(out IAudioSessionEnumerator sessionEnum);
                    if (hr != 0 || sessionEnum is null) return false;

                    try
                    {
                        sessionEnum.GetCount(out int count);
                        bool modified = false;
                        for (int i = 0; i < count; i++)
                        {
                            hr = sessionEnum.GetSession(i, out object sessionObj);
                            if (hr != 0 || sessionObj is null) continue;

                            try
                            {
                                if (sessionObj is IAudioSessionControl2 ctl2 && sessionObj is ISimpleAudioVolume vol)
                                {
                                    ctl2.GetProcessId(out uint pid);
                                    if (pid == targetPid)
                                    {
                                        action(vol);
                                        modified = true;
                                    }
                                }
                            }
                            finally { Marshal.ReleaseComObject(sessionObj); }
                        }
                        return modified;
                    }
                    finally { Marshal.ReleaseComObject(sessionEnum); }
                }
                finally { Marshal.ReleaseComObject(mgr); }
            }
            finally { Marshal.ReleaseComObject(dev); }
        }
        catch { return false; }
        finally { Marshal.ReleaseComObject(enumerator); }
    }

    public static List<AudioDeviceInfo> GetAudioDevices(bool isRender = true)
    {
        var list = new List<AudioDeviceInfo>();
        var enumerator = (IMMDeviceEnumerator)(new MMDeviceEnumerator());
        try
        {
            int flow = isRender ? 0 : 1;
            int hr = enumerator.EnumAudioEndpoints(flow, 1 /* DEVICE_STATE_ACTIVE */, out IMMDeviceCollection col);
            if (hr != 0 || col is null) return list;

            try
            {
                string defaultId = "";
                if (enumerator.GetDefaultAudioEndpoint(flow, 0, out IMMDevice defaultDev) == 0 && defaultDev != null)
                {
                    try { defaultDev.GetId(out defaultId); }
                    finally { Marshal.ReleaseComObject(defaultDev); }
                }

                col.GetCount(out int count);
                for (int i = 0; i < count; i++)
                {
                    if (col.Item(i, out IMMDevice dev) != 0 || dev is null) continue;
                    try
                    {
                        dev.GetId(out string id);
                        string name = id;
                        if (dev.OpenPropertyStore(0 /* STGM_READ */, out IPropertyStore store) == 0 && store != null)
                        {
                            try
                            {
                                var key = PKEY_Device_FriendlyName;
                                if (store.GetValue(ref key, out PROPVARIANT pv) == 0 && pv.pwszVal != IntPtr.Zero)
                                {
                                    name = Marshal.PtrToStringUni(pv.pwszVal) ?? id;
                                }
                            }
                            finally { Marshal.ReleaseComObject(store); }
                        }

                        list.Add(new AudioDeviceInfo
                        {
                            Id = id,
                            Name = name,
                            IsDefault = string.Equals(id, defaultId, StringComparison.OrdinalIgnoreCase),
                            IsInput = !isRender
                        });
                    }
                    finally { Marshal.ReleaseComObject(dev); }
                }
            }
            finally { Marshal.ReleaseComObject(col); }
        }
        catch { }
        finally { Marshal.ReleaseComObject(enumerator); }

        return list;
    }

    public static bool SetDefaultAudioDevice(string deviceId)
    {
        try
        {
            var policy = (IPolicyConfig)(new PolicyConfig());
            try
            {
                // Set default for eConsole (0), eMultimedia (1), and eCommunications (2)
                policy.SetDefaultEndpoint(deviceId, 0);
                policy.SetDefaultEndpoint(deviceId, 1);
                policy.SetDefaultEndpoint(deviceId, 2);
                return true;
            }
            finally
            {
                Marshal.ReleaseComObject(policy);
            }
        }
        catch
        {
            return false;
        }
    }

    public static MicrophoneState GetMicrophoneState()
    {
        var enumerator = (IMMDeviceEnumerator)(new MMDeviceEnumerator());
        try
        {
            int hr = enumerator.GetDefaultAudioEndpoint(1 /* eCapture */, 0 /* eConsole */, out IMMDevice dev);
            if (hr != 0 || dev is null) return new MicrophoneState { Level = 0, IsMuted = true };

            try
            {
                Guid iid = typeof(IAudioEndpointVolume).GUID;
                hr = dev.Activate(ref iid, 1, IntPtr.Zero, out object o);
                if (hr != 0 || o is null) return new MicrophoneState { Level = 0, IsMuted = true };

                var vol = (IAudioEndpointVolume)o;
                try
                {
                    vol.GetMasterVolumeLevelScalar(out float level);
                    vol.GetMute(out bool isMuted);
                    return new MicrophoneState
                    {
                        Level = (int)Math.Round(level * 100f),
                        IsMuted = isMuted
                    };
                }
                finally { Marshal.ReleaseComObject(vol); }
            }
            finally { Marshal.ReleaseComObject(dev); }
        }
        catch { return new MicrophoneState { Level = 0, IsMuted = true }; }
        finally { Marshal.ReleaseComObject(enumerator); }
    }

    public static bool SetMicrophoneState(int levelPercent, bool? isMuted = null)
    {
        var enumerator = (IMMDeviceEnumerator)(new MMDeviceEnumerator());
        try
        {
            int hr = enumerator.GetDefaultAudioEndpoint(1, 0, out IMMDevice dev);
            if (hr != 0 || dev is null) return false;

            try
            {
                Guid iid = typeof(IAudioEndpointVolume).GUID;
                hr = dev.Activate(ref iid, 1, IntPtr.Zero, out object o);
                if (hr != 0 || o is null) return false;

                var vol = (IAudioEndpointVolume)o;
                try
                {
                    Guid empty = Guid.Empty;
                    vol.SetMasterVolumeLevelScalar(Math.Clamp(levelPercent / 100f, 0f, 1f), ref empty);
                    if (isMuted.HasValue)
                    {
                        vol.SetMute(isMuted.Value, ref empty);
                    }
                    return true;
                }
                finally { Marshal.ReleaseComObject(vol); }
            }
            finally { Marshal.ReleaseComObject(dev); }
        }
        catch { return false; }
        finally { Marshal.ReleaseComObject(enumerator); }
    }
}

public sealed class AppAudioSession
{
    public int ProcessId { get; set; }
    public int Pid => ProcessId;
    public string ProcessName { get; set; } = string.Empty;
    public int VolumePercent { get; set; }
    public bool IsMuted { get; set; }
}

public sealed class AudioDeviceInfo
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public bool IsDefault { get; set; }
    public bool IsInput { get; set; }
}

public sealed class MicrophoneState
{
    public int Level { get; set; }
    public bool IsMuted { get; set; }
}
