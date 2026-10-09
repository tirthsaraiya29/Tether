using System;
using System.Runtime.InteropServices;

namespace Tether.SessionHelper;

internal static class AudioController
{
    [ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")]
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

    private static IAudioEndpointVolume OpenEndpoint()
    {
        var enumerator = (IMMDeviceEnumerator)(new MMDeviceEnumerator());
        int hr = enumerator.GetDefaultAudioEndpoint(0, 0, out IMMDevice dev);
        if (hr != 0 || dev is null) throw new InvalidOperationException($"GetDefaultAudioEndpoint hr=0x{hr:X8}");

        Guid iid = typeof(IAudioEndpointVolume).GUID;
        hr = dev.Activate(ref iid, 1, IntPtr.Zero, out object o);
        Marshal.ReleaseComObject(dev);
        Marshal.ReleaseComObject(enumerator);

        if (hr != 0 || o is null) throw new InvalidOperationException($"Activate hr=0x{hr:X8}");
        return (IAudioEndpointVolume)o;
    }

    public static int GetMasterVolume()
    {
        var vol = OpenEndpoint();
        try
        {
            vol.GetMasterVolumeLevelScalar(out float level);
            return (int)Math.Round(level * 100f);
        }
        finally { Marshal.ReleaseComObject(vol); }
    }

    public static void SetMasterVolume(int percent)
    {
        var vol = OpenEndpoint();
        try
        {
            Guid empty = Guid.Empty;
            vol.SetMasterVolumeLevelScalar(Math.Clamp(percent / 100f, 0f, 1f), ref empty);
        }
        finally { Marshal.ReleaseComObject(vol); }
    }

    public static int AdjustMasterVolume(int delta)
    {
        var vol = OpenEndpoint();
        try
        {
            vol.GetMasterVolumeLevelScalar(out float cur);
            int current = (int)Math.Round(cur * 100f);
            int target = Math.Clamp(current + delta, 0, 100);
            Guid empty = Guid.Empty;
            vol.SetMasterVolumeLevelScalar(target / 100f, ref empty);
            return target;
        }
        finally { Marshal.ReleaseComObject(vol); }
    }

    public static bool ToggleMute()
    {
        var vol = OpenEndpoint();
        try
        {
            vol.GetMute(out bool muted);
            Guid empty = Guid.Empty;
            vol.SetMute(!muted, ref empty);
            return !muted;
        }
        finally { Marshal.ReleaseComObject(vol); }
    }
}