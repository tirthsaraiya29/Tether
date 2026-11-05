using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Tether.SessionHelper;

public static class LockStateDetector
{
    private const uint DESKTOP_SWITCHDESKTOP = 0x0100;
    private const int ERROR_ACCESS_DENIED = 5;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr OpenInputDesktop(uint dwFlags, bool fInherit, uint dwDesiredAccess);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool CloseDesktop(IntPtr hDesktop);

    private static long _lastCheckTick;
    private static bool _cachedIsLocked;
    private static readonly object _cacheLock = new();
    private const long CacheTtlMs = 150; // Cache check for 150ms to sustain 120Hz input rates without overhead

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
            // OpenInputDesktop opens the desktop that currently receives user input.
            // If the workstation is unlocked, OpenInputDesktop succeeds (~0.1ms) and returns a handle.
            // If the workstation is locked (or switched to Winlogon/Secure Desktop), OpenInputDesktop
            // fails with ERROR_ACCESS_DENIED because user processes are barred from Winlogon.
            IntPtr hDesktop = OpenInputDesktop(0, false, DESKTOP_SWITCHDESKTOP);
            if (hDesktop != IntPtr.Zero)
            {
                CloseDesktop(hDesktop);
                return false; // Unlocked and interactive desktop active
            }

            int lastError = Marshal.GetLastWin32Error();
            if (lastError == ERROR_ACCESS_DENIED)
            {
                return true; // Input desktop switched to secure/winlogon desktop -> LOCKED
            }

            // 2. Secondary fallback for non-standard desktop environments:
            var logonProcesses = Process.GetProcessesByName("LogonUI");
            try
            {
                if (logonProcesses.Length > 0)
                {
                    return true;
                }
            }
            finally
            {
                foreach (var p in logonProcesses)
                {
                    try { p.Dispose(); } catch { }
                }
            }

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
