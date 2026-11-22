using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Tether.LinuxDaemon.Common;
using Tether.Shared.Logging;

namespace Tether.LinuxDaemon.Capabilities;

public static class LinuxNotificationController
{
    public static async Task<bool> ShowNotificationOnDesktopAsync(string title, string body, string app, ITetherLogger logger)
    {
        try
        {
            var session = PlatformDetection.GetActiveSessionInfo();
            string uidStr = session.Uid > 0 ? session.Uid.ToString() : "1000";
            string busAddr = $"unix:path=/run/user/{uidStr}/bus";

            string safeApp = string.IsNullOrWhiteSpace(app) ? "Phone" : app.Replace("\"", "\\\"");
            string safeTitle = string.IsNullOrWhiteSpace(title) ? "Notification" : title.Replace("\"", "\\\"");
            string safeBody = string.IsNullOrWhiteSpace(body) ? "" : body.Replace("\"", "\\\"");

            var psi = new ProcessStartInfo
            {
                FileName = "notify-send",
                Arguments = $"-a \"{safeApp}\" \"{safeTitle}\" \"{safeBody}\"",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            psi.EnvironmentVariables["DBUS_SESSION_BUS_ADDRESS"] = busAddr;

            using var p = Process.Start(psi);
            if (p != null)
            {
                await p.WaitForExitAsync();
                return p.ExitCode == 0;
            }
        }
        catch (Exception ex)
        {
            logger.Warning($"LinuxNotificationController: notify-send failed: {ex.Message}");
        }

        return false;
    }

    public static async Task<bool> DismissNotificationAsync(uint notifId, ITetherLogger logger)
    {
        try
        {
            var session = PlatformDetection.GetActiveSessionInfo();
            string uidStr = session.Uid > 0 ? session.Uid.ToString() : "1000";
            string busAddr = $"unix:path=/run/user/{uidStr}/bus";

            var psi = new ProcessStartInfo
            {
                FileName = "gdbus",
                Arguments = $"call --session --dest org.freedesktop.Notifications --object-path /org/freedesktop/Notifications --method org.freedesktop.Notifications.CloseNotification {notifId}",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            psi.EnvironmentVariables["DBUS_SESSION_BUS_ADDRESS"] = busAddr;

            using var p = Process.Start(psi);
            if (p != null)
            {
                await p.WaitForExitAsync();
                return p.ExitCode == 0;
            }
        }
        catch (Exception ex)
        {
            logger.Debug($"LinuxNotificationController: Dismiss notification {notifId} error: {ex.Message}");
        }

        return false;
    }
}
