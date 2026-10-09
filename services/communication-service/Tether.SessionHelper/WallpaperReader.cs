using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Win32;

namespace Tether.SessionHelper;

public static class WallpaperReader
{
    public static string? GetCurrentWallpaperPath()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Control Panel\Desktop");
            string? wallpaper = key?.GetValue("WallPaper") as string;
            if (!string.IsNullOrWhiteSpace(wallpaper) && File.Exists(wallpaper))
            {
                return wallpaper;
            }

            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string transcoded = Path.Combine(appData, @"Microsoft\Windows\Themes\TranscodedWallpaper");
            if (File.Exists(transcoded))
            {
                return transcoded;
            }
        }
        catch
        {
            // Ignore registry read errors
        }
        return null;
    }

    public static (string? b64, string? hash) GetDownscaledWallpaperBase64AndHash(int maxW = 640, int maxH = 400)
    {
        string? path = GetCurrentWallpaperPath();
        if (string.IsNullOrEmpty(path) || !File.Exists(path))
        {
            return (null, null);
        }

        try
        {
            using var src = Image.FromFile(path);
            int origW = src.Width;
            int origH = src.Height;

            double ratioX = (double)maxW / origW;
            double ratioY = (double)maxH / origH;
            double ratio = Math.Min(ratioX, ratioY);

            int newW = Math.Max(1, (int)(origW * ratio));
            int newH = Math.Max(1, (int)(origH * ratio));

            using var destImage = new Bitmap(newW, newH);
            using (var graphics = Graphics.FromImage(destImage))
            {
                graphics.CompositingMode = CompositingMode.SourceCopy;
                graphics.CompositingQuality = CompositingQuality.HighSpeed;
                graphics.InterpolationMode = InterpolationMode.Bilinear;
                graphics.SmoothingMode = SmoothingMode.HighSpeed;
                graphics.PixelOffsetMode = PixelOffsetMode.HighSpeed;

                using var wrapMode = new ImageAttributes();
                wrapMode.SetWrapMode(WrapMode.TileFlipXY);
                graphics.DrawImage(src, new Rectangle(0, 0, newW, newH), 0, 0, origW, origH, GraphicsUnit.Pixel, wrapMode);
            }

            using var ms = new MemoryStream();
            destImage.Save(ms, ImageFormat.Jpeg);

            byte[] bytes = ms.ToArray();
            string b64 = Convert.ToBase64String(bytes);

            using var sha256 = SHA256.Create();
            byte[] hashBytes = sha256.ComputeHash(bytes);
            string hash = Convert.ToHexString(hashBytes);

            return (b64, hash);
        }
        catch
        {
            try
            {
                // Fallback: read raw file bytes if image decoding/resizing fails
                byte[] rawBytes = File.ReadAllBytes(path);
                if (rawBytes.Length > 0 && rawBytes.Length <= 500_000)
                {
                    string b64 = Convert.ToBase64String(rawBytes);
                    using var sha256 = SHA256.Create();
                    byte[] hashBytes = sha256.ComputeHash(rawBytes);
                    string hash = Convert.ToHexString(hashBytes);
                    return (b64, hash);
                }
            }
            catch { }

            return (null, null);
        }
    }
}
