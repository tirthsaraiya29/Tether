using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Tether.SessionHelper;

public static class LockStateDetector
{
    private const uint DESKTOP_SWITCHDESKTOP = 0x0100;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr OpenInputDesktop(uint dwFlags, bool fInherit, uint dwDesiredAccess);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool CloseDesktop(IntPtr hDesktop);

    public static bool IsLocked()
    {
        try
        {
            // 1. Primary check: LogonUI process. Active on lock screen / credential screen.
            var logonProcesses = Process.GetProcessesByName("LogonUI");
            if (logonProcesses.Length > 0)
            {
                foreach (var p in logonProcesses) { try { p.Dispose(); } catch { } }
                return true;
            }

            // 2. Secondary check: OpenInputDesktop when desktop handle access is available
            IntPtr hDesktop = OpenInputDesktop(0, false, DESKTOP_SWITCHDESKTOP);
            if (hDesktop != IntPtr.Zero)
            {
                CloseDesktop(hDesktop);
                return false;
            }

            // If LogonUI is not active, user is actively at desktop (unlocked)
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
