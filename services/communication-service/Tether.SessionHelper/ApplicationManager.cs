using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

namespace Tether.SessionHelper;

internal sealed class ApplicationManager
{
    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    private static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);

    [DllImport("user32.dll")]
    private static extern IntPtr PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool IsIconic(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool IsZoomed(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", EntryPoint = "GetClassLongPtrW")]
    private static extern IntPtr GetClassLongPtr(IntPtr hWnd, int nIndex);

    private const uint WM_GETICON = 0x007F;
    private const int ICON_SMALL = 0;
    private const int ICON_BIG = 1;
    private const int GCLP_HICON = -14;
    private const int GCLP_HICONSM = -34;

    private const int SW_RESTORE = 9;
    private const int SW_MINIMIZE = 6;
    private const int SW_MAXIMIZE = 3;
    private const uint WM_CLOSE = 0x0010;
    private const uint SWP_NOZORDER = 0x0004;
    private const uint SWP_SHOWWINDOW = 0x0040;

    public static List<InstalledAppInfo> GetInstalledApplications()
    {
        var list = new List<InstalledAppInfo>();
        var seenNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var dirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms),
            Environment.GetFolderPath(Environment.SpecialFolder.Programs),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu),
            Environment.GetFolderPath(Environment.SpecialFolder.StartMenu)
        };

        foreach (var dir in dirs)
        {
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;
            try
            {
                var shortcuts = Directory.GetFiles(dir, "*.lnk", SearchOption.AllDirectories);
                foreach (var sc in shortcuts)
                {
                    string name = Path.GetFileNameWithoutExtension(sc);
                    if (seenNames.Add(name) && !name.StartsWith("Uninstall", StringComparison.OrdinalIgnoreCase))
                    {
                        list.Add(new InstalledAppInfo
                        {
                            Name = name,
                            ShortcutPath = sc
                        });
                    }
                }
            }
            catch { }
        }

        var regRoots = new[]
        {
            Microsoft.Win32.Registry.LocalMachine,
            Microsoft.Win32.Registry.CurrentUser
        };

        var regPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        };

        foreach (var root in regRoots)
        {
            foreach (var rPath in regPaths)
            {
                try
                {
                    using var baseKey = root.OpenSubKey(rPath);
                    if (baseKey == null) continue;
                    foreach (var subName in baseKey.GetSubKeyNames())
                    {
                        try
                        {
                            using var sub = baseKey.OpenSubKey(subName);
                            if (sub == null) continue;
                            string? dispName = sub.GetValue("DisplayName") as string;
                            if (string.IsNullOrWhiteSpace(dispName) || seenNames.Contains(dispName)) continue;
                            if (sub.GetValue("SystemComponent") is int sys && sys == 1) continue;
                            if (sub.GetValue("ParentKeyName") != null) continue;

                            string? installLoc = sub.GetValue("InstallLocation") as string;
                            string? displayIcon = sub.GetValue("DisplayIcon") as string;
                            string launchTarget = !string.IsNullOrEmpty(displayIcon) && displayIcon.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && File.Exists(displayIcon)
                                ? displayIcon
                                : (!string.IsNullOrEmpty(installLoc) ? installLoc : dispName);

                            if (seenNames.Add(dispName))
                            {
                                string? appIconB64 = GetAppIconBase64(launchTarget);
                                list.Add(new InstalledAppInfo
                                {
                                    Name = dispName,
                                    ShortcutPath = launchTarget,
                                    IconB64 = appIconB64
                                });
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }

        return list;
    }

    public static bool LaunchApplication(string pathOrName, string? arguments = null)
    {
        if (string.IsNullOrWhiteSpace(pathOrName)) return false;

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = pathOrName,
                Arguments = arguments ?? "",
                UseShellExecute = true
            };
            Process.Start(psi);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static List<RunningWindowInfo> GetRunningWindows()
    {
        var list = new List<RunningWindowInfo>();
        EnumWindows((hWnd, lParam) =>
        {
            try
            {
                if (!IsWindowVisible(hWnd)) return true;

                var sb = new StringBuilder(256);
                GetWindowText(hWnd, sb, 256);
                string title = sb.ToString().Trim();
                if (string.IsNullOrEmpty(title) || title == "Program Manager") return true;

                GetWindowThreadProcessId(hWnd, out uint pid);
                string procName = "";
                try
                {
                    using var proc = Process.GetProcessById((int)pid);
                    procName = proc.ProcessName;
                }
                catch { }

                string? iconB64 = GetWindowIconBase64(hWnd, (int)pid);
                list.Add(new RunningWindowInfo
                {
                    Hwnd = hWnd.ToInt64(),
                    Title = title,
                    ProcessName = procName,
                    ProcessId = (int)pid,
                    IsMinimized = IsIconic(hWnd),
                    IsMaximized = IsZoomed(hWnd),
                    IconB64 = iconB64
                });
            }
            catch { }
            return true;
        }, IntPtr.Zero);

        return list;
    }

    public static bool SwitchWindow(IntPtr hwnd)
    {
        ShowWindow(hwnd, SW_RESTORE);
        return SetForegroundWindow(hwnd);
    }

    public static bool SetWindowState(IntPtr hwnd, string state)
    {
        var screen = Screen.PrimaryScreen?.WorkingArea ?? new System.Drawing.Rectangle(0, 0, 1920, 1080);

        switch (state.ToLowerInvariant())
        {
            case "minimize":
                return ShowWindow(hwnd, SW_MINIMIZE);
            case "maximize":
                return ShowWindow(hwnd, SW_MAXIMIZE);
            case "restore":
                return ShowWindow(hwnd, SW_RESTORE);
            case "snap_left":
                ShowWindow(hwnd, SW_RESTORE);
                return SetWindowPos(hwnd, IntPtr.Zero, screen.X, screen.Y, screen.Width / 2, screen.Height, SWP_NOZORDER | SWP_SHOWWINDOW);
            case "snap_right":
                ShowWindow(hwnd, SW_RESTORE);
                return SetWindowPos(hwnd, IntPtr.Zero, screen.X + (screen.Width / 2), screen.Y, screen.Width / 2, screen.Height, SWP_NOZORDER | SWP_SHOWWINDOW);
            default:
                return false;
        }
    }

    public static bool CloseWindow(IntPtr hwnd, bool force = false)
    {
        if (force)
        {
            GetWindowThreadProcessId(hwnd, out uint pid);
            if (pid != 0)
            {
                try
                {
                    using var proc = Process.GetProcessById((int)pid);
                    proc.Kill(true);
                    return true;
                }
                catch { return false; }
            }
        }

        PostMessage(hwnd, WM_CLOSE, IntPtr.Zero, IntPtr.Zero);
        return true;
    }

    public static string? GetWindowIconBase64(IntPtr hWnd, int pid)
    {
        try
        {
            IntPtr hIcon = SendMessage(hWnd, WM_GETICON, (IntPtr)ICON_SMALL, IntPtr.Zero);
            if (hIcon == IntPtr.Zero) hIcon = SendMessage(hWnd, WM_GETICON, (IntPtr)ICON_BIG, IntPtr.Zero);
            if (hIcon == IntPtr.Zero) hIcon = GetClassLongPtr(hWnd, GCLP_HICONSM);
            if (hIcon == IntPtr.Zero) hIcon = GetClassLongPtr(hWnd, GCLP_HICON);

            if (hIcon != IntPtr.Zero)
            {
                using var icon = (System.Drawing.Icon)System.Drawing.Icon.FromHandle(hIcon).Clone();
                using var bmp = icon.ToBitmap();
                using var ms = new MemoryStream();
                bmp.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
                return Convert.ToBase64String(ms.ToArray());
            }

            if (pid > 0)
            {
                using var proc = Process.GetProcessById(pid);
                string? exe = proc.MainModule?.FileName;
                if (!string.IsNullOrEmpty(exe) && File.Exists(exe))
                {
                    using var icon = System.Drawing.Icon.ExtractAssociatedIcon(exe);
                    if (icon != null)
                    {
                        using var bmp = icon.ToBitmap();
                        using var ms = new MemoryStream();
                        bmp.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
                        return Convert.ToBase64String(ms.ToArray());
                    }
                }
            }
        }
        catch { }
        return null;
    }

    public static string? GetAppIconBase64(string path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return null;
            using var icon = System.Drawing.Icon.ExtractAssociatedIcon(path);
            if (icon != null)
            {
                using var bmp = icon.ToBitmap();
                using var ms = new MemoryStream();
                bmp.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
                return Convert.ToBase64String(ms.ToArray());
            }
        }
        catch { }
        return null;
    }
}

public sealed class InstalledAppInfo
{
    public string Name { get; set; } = string.Empty;
    public string ShortcutPath { get; set; } = string.Empty;
    public string Path => ShortcutPath;
    public string? IconB64 { get; set; }
}

public sealed class RunningWindowInfo
{
    public long Hwnd { get; set; }
    public string Title { get; set; } = string.Empty;
    public string ProcessName { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public int Pid => ProcessId;
    public bool IsMinimized { get; set; }
    public bool IsMaximized { get; set; }
    public string? IconB64 { get; set; }
}
