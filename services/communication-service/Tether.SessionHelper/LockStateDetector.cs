using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Tether.SessionHelper;

public static class LockStateDetector
{
    private const uint DESKTOP_READOBJECTS = 0x0001;
    private const int UOI_NAME = 2;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr OpenInputDesktop(uint dwFlags, bool fInherit, uint dwDesiredAccess);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool CloseDesktop(IntPtr hDesktop);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool GetUserObjectInformation(IntPtr hObj, int nIndex, [Out] StringBuilder pvInfo, int nLength, out int lpnLengthNeeded);

    private static long _lastCheckTick;
    private static bool _cachedIsLocked;
    private static readonly object _cacheLock = new();
    private const long CacheTtlMs = 150; // Cache check for 150ms to sustain 120Hz input rates without overhead
    private static readonly int CurrentSessionId = Process.GetCurrentProcess().SessionId;

    public static bool IsLocked()
    {
        long now = Environment.TickCount64;
        lock (_cacheLock)
        {
            if (now - _lastCheckTick < CacheTtlMs)
            {
                return _cachedIsLocked;
            }

            _cachedIsLocked = QueryLockStateDirect();
            _lastCheckTick = now;
            return _cachedIsLocked;
        }
    }

    private static bool QueryLockStateDirect()
    {
        try
        {
            // 1. Authoritative check in interactive user session:
            // Attempt to open the input desktop with minimal read access.
            IntPtr hDesktop = OpenInputDesktop(0, false, DESKTOP_READOBJECTS);
            if (hDesktop != IntPtr.Zero)
            {
                try
                {
                    var sb = new StringBuilder(256);
                    if (GetUserObjectInformation(hDesktop, UOI_NAME, sb, sb.Capacity, out _))
                    {
                        string deskName = sb.ToString();
                        if (string.Equals(deskName, "Default", StringComparison.OrdinalIgnoreCase))
                        {
                            return false; // Interactive unlocked desktop
                        }
                        if (string.Equals(deskName, "Winlogon", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(deskName, "Screen-saver", StringComparison.OrdinalIgnoreCase))
                        {
                            return true; // Explicit lock/screensaver desktop
                        }
                    }
                }
                finally
                {
                    CloseDesktop(hDesktop);
                }
            }

            // 2. Corroborative check:
            // Check if LogonUI is actively executing in the current session.
            var logonProcesses = Process.GetProcessesByName("LogonUI");
            try
            {
                foreach (var p in logonProcesses)
                {
                    try
                    {
                        if (p.SessionId == CurrentSessionId)
                        {
                            return true;
                        }
                    }
                    catch { }
                }
            }
            finally
            {
                foreach (var p in logonProcesses)
                {
                    try { p.Dispose(); } catch { }
                }
            }

            // If LogonUI is not running in this session, assume unlocked rather than falsely dropping inputs
            return false;
        }
        catch
        {
            return false;
        }
    }

    public static string GetLockStateString()
    {
        return IsLocked() ? "LOCKED" : "UNLOCKED";
    }
}
