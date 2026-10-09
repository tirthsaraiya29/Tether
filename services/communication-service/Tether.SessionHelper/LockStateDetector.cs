using System;
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
        IntPtr hDesktop = OpenInputDesktop(0, false, DESKTOP_SWITCHDESKTOP);
        if (hDesktop == IntPtr.Zero)
        {
            // Failed to open active input desktop -> locked / LogonUI active
            return true;
        }
        CloseDesktop(hDesktop);
        return false;
    }

    public static string GetLockStateString()
    {
        return IsLocked() ? "LOCKED" : "UNLOCKED";
    }
}
