using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;

namespace Tether.SessionHelper;

internal sealed class ScreenCaptureEngine
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
    private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

    [DllImport("user32.dll")]
    private static extern bool PrintWindow(IntPtr hwnd, IntPtr hdcBlt, uint nFlags);

    [DllImport("user32.dll")]
    private static extern IntPtr GetDesktopWindow();

    [DllImport("user32.dll")]
    private static extern IntPtr GetWindowDC(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern int ReleaseDC(IntPtr hWnd, IntPtr hDC);

    [DllImport("gdi32.dll")]
    private static extern bool BitBlt(IntPtr hObject, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hObjectSource, int nXSrc, int nYSrc, int dwRop);

    [DllImport("gdi32.dll")]
    private static extern bool StretchBlt(IntPtr hdcDest, int nXOriginDest, int nYOriginDest, int nWidthDest, int nHeightDest, IntPtr hdcSrc, int nXOriginSrc, int nYOriginSrc, int nWidthSrc, int nHeightSrc, int dwRop);

    [DllImport("gdi32.dll")]
    private static extern int SetStretchBltMode(IntPtr hdc, int nStretchMode);

    private const int SRCCOPY = 0x00CC0020;
    private const int HALFTONE = 4;
    private const uint PW_RENDERFULLCONTENT = 0x00000002;

    private static readonly ImageCodecInfo? _jpegCodec = GetEncoder(ImageFormat.Jpeg);

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
        public int Width => Right - Left;
        public int Height => Bottom - Top;
    }

    public static byte[]? CaptureFullScreen(int quality = 70, int maxWidth = 1920, int maxHeight = 1080)
    {
        try
        {
            var bounds = Screen.PrimaryScreen?.Bounds ?? new Rectangle(0, 0, 1920, 1080);
            float ratio = Math.Min(1f, Math.Min((float)maxWidth / Math.Max(1, bounds.Width), (float)maxHeight / Math.Max(1, bounds.Height)));
            int targetW = Math.Max(1, (int)(bounds.Width * ratio));
            int targetH = Math.Max(1, (int)(bounds.Height * ratio));

            using var bmp = new Bitmap(targetW, targetH, PixelFormat.Format32bppRgb);
            using (var g = Graphics.FromImage(bmp))
            {
                IntPtr destHdc = g.GetHdc();
                IntPtr deskHwnd = GetDesktopWindow();
                IntPtr srcHdc = GetWindowDC(deskHwnd);
                try
                {
                    SetStretchBltMode(destHdc, HALFTONE);
                    StretchBlt(destHdc, 0, 0, targetW, targetH, srcHdc, bounds.X, bounds.Y, bounds.Width, bounds.Height, SRCCOPY);
                }
                finally
                {
                    ReleaseDC(deskHwnd, srcHdc);
                    g.ReleaseHdc(destHdc);
                }
            }

            return EncodeBitmap(bmp, quality, targetW, targetH);
        }
        catch
        {
            return null;
        }
    }

    public static byte[]? CaptureWindow(IntPtr hwnd, int quality = 75)
    {
        try
        {
            if (!IsWindowVisible(hwnd)) return null;
            if (!GetWindowRect(hwnd, out var rect) || rect.Width <= 0 || rect.Height <= 0) return null;

            using var bmp = new Bitmap(rect.Width, rect.Height, PixelFormat.Format32bppRgb);
            using (var g = Graphics.FromImage(bmp))
            {
                IntPtr hdc = g.GetHdc();
                try
                {
                    bool ok = PrintWindow(hwnd, hdc, PW_RENDERFULLCONTENT);
                    if (!ok)
                    {
                        PrintWindow(hwnd, hdc, 0);
                    }
                }
                finally
                {
                    g.ReleaseHdc(hdc);
                }
            }

            return EncodeBitmap(bmp, quality, rect.Width, rect.Height);
        }
        catch
        {
            return null;
        }
    }

    public static List<WindowInfo> GetOpenWindows()
    {
        var list = new List<WindowInfo>();
        EnumWindows((hWnd, lParam) =>
        {
            try
            {
                if (!IsWindowVisible(hWnd)) return true;

                var sb = new StringBuilder(256);
                GetWindowText(hWnd, sb, 256);
                string title = sb.ToString().Trim();
                if (string.IsNullOrEmpty(title) || title == "Program Manager") return true;

                GetWindowRect(hWnd, out var r);
                if (r.Width < 50 || r.Height < 50) return true;

                GetWindowThreadProcessId(hWnd, out uint pid);
                string procName = "";
                try
                {
                    using var proc = Process.GetProcessById((int)pid);
                    procName = proc.ProcessName;
                }
                catch { }

                string? winIconB64 = ApplicationManager.GetWindowIconBase64(hWnd, (int)pid);
                list.Add(new WindowInfo
                {
                    Hwnd = hWnd.ToInt64(),
                    Title = title,
                    ProcessName = procName,
                    ProcessId = (int)pid,
                    Width = r.Width,
                    Height = r.Height,
                    IconB64 = winIconB64
                });
            }
            catch { }
            return true;
        }, IntPtr.Zero);

        return list;
    }

    private static byte[] EncodeBitmap(Bitmap source, int quality, int maxWidth, int maxHeight)
    {
        Bitmap finalBmp = source;
        bool resized = false;

        if (source.Width > maxWidth || source.Height > maxHeight)
        {
            float ratio = Math.Min((float)maxWidth / source.Width, (float)maxHeight / source.Height);
            int newW = Math.Max(1, (int)(source.Width * ratio));
            int newH = Math.Max(1, (int)(source.Height * ratio));

            finalBmp = new Bitmap(newW, newH, PixelFormat.Format32bppRgb);
            using (var g = Graphics.FromImage(finalBmp))
            {
                g.InterpolationMode = InterpolationMode.Bilinear;
                g.DrawImage(source, 0, 0, newW, newH);
            }
            resized = true;
        }

        try
        {
            using var ms = new MemoryStream();
            if (_jpegCodec != null)
            {
                using var encoderParams = new EncoderParameters(1);
                using var param = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, (long)Math.Clamp(quality, 10, 100));
                encoderParams.Param[0] = param;
                finalBmp.Save(ms, _jpegCodec, encoderParams);
            }
            else
            {
                finalBmp.Save(ms, ImageFormat.Jpeg);
            }
            return ms.ToArray();
        }
        finally
        {
            if (resized) finalBmp.Dispose();
        }
    }

    private static ImageCodecInfo? GetEncoder(ImageFormat format)
    {
        foreach (var codec in ImageCodecInfo.GetImageEncoders())
        {
            if (codec.FormatID == format.Guid) return codec;
        }
        return null;
    }
}

public sealed class WindowInfo
{
    public long Hwnd { get; set; }
    public string Title { get; set; } = string.Empty;
    public string ProcessName { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public int Pid => ProcessId;
    public int Width { get; set; }
    public int Height { get; set; }
    public string? IconB64 { get; set; }
}
