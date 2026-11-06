using System;
using System.Diagnostics;
using System.IO;

namespace Tether.DesktopUI.Updates
{
    public static class WindowsNotificationHelper
    {
        /// <summary>
        /// Displays a high-priority, actionable Windows notification to alert the user of a critical Tether update.
        /// </summary>
        public static void ShowHighPriorityUpdateNotification(string newVersion, string summary, Action? onUpdateNow = null)
        {
            try
            {
                // Escape strings for PowerShell XML payload
                string safeVersion = newVersion.Replace("\"", "").Replace("'", "");
                string safeSummary = (summary.Length > 120 ? summary.Substring(0, 117) + "..." : summary)
                    .Replace("\"", "'").Replace("\r", " ").Replace("\n", " ");

                string psScript = $@"
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

$template = @""
<toast scenario='urgent'>
    <visual>
        <binding template='ToastGeneric'>
            <text>Critical Tether Update Ready ({safeVersion})</text>
            <text>{safeSummary}</text>
            <text placement='attribution'>Tether Security &amp; Platform</text>
        </binding>
    </visual>
    <actions>
        <action content='Update Now' arguments='action=update&amp;ver={safeVersion}' activationType='foreground'/>
        <action content='Remind in 4h' arguments='action=snooze&amp;ver={safeVersion}' activationType='background'/>
    </actions>
</toast>
""@

$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml($template)
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
$toast.Priority = [Windows.UI.Notifications.ToastNotificationPriority]::High
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Tether').Show($toast)
";

                var startInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -WindowStyle Hidden -Command \"{psScript.Replace("\r\n", " ").Replace("\n", " ")}\"",
                    CreateNoWindow = true,
                    UseShellExecute = false
                };

                Process.Start(startInfo);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[WindowsNotificationHelper] Failed to show toast notification: {ex.Message}");
            }
        }
    }
}
