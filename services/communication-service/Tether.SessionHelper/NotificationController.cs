using System;
using System.IO;
using System.Threading.Tasks;
using Windows.Data.Xml.Dom;
using Windows.UI.Notifications;
using Windows.UI.Notifications.Management;

namespace Tether.SessionHelper;

internal sealed class NotificationController
{
    private static UserNotificationListener? _listener;
    private static Action<NotificationPayload>? _onNotificationPosted;

    public static async Task InitializeAsync(Action<NotificationPayload> onNotificationPosted)
    {
        _onNotificationPosted = onNotificationPosted;
        try
        {
            _listener = UserNotificationListener.Current;
            var access = await _listener.RequestAccessAsync();
            if (access == UserNotificationListenerAccessStatus.Allowed)
            {
                _listener.NotificationChanged += async (s, e) =>
                {
                    if (e.ChangeKind == UserNotificationChangedKind.Added)
                    {
                        var notif = _listener.GetNotification(e.UserNotificationId);
                        if (notif != null)
                        {
                            var payload = ExtractNotificationPayload(notif);
                            if (payload != null)
                            {
                                _onNotificationPosted?.Invoke(payload);
                            }
                        }
                    }
                };
            }
        }
        catch { }
    }

    public static async Task<bool> DismissNotificationAsync(uint notificationId)
    {
        try
        {
            if (_listener == null) _listener = UserNotificationListener.Current;
            _listener.RemoveNotification(notificationId);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static System.Windows.Forms.NotifyIcon? _fallbackNotifyIcon;
    private static readonly object _notifyLock = new();

    public static void ShowToastOnDesktop(string title, string body, string? sourceApp = null)
    {
        string appName = string.IsNullOrEmpty(sourceApp) ? "Tether" : sourceApp;
        bool toastShown = false;
        try
        {
            string xml = $@"
<toast>
    <visual>
        <binding template='ToastGeneric'>
            <text>{System.Security.SecurityElement.Escape(title)}</text>
            <text>{System.Security.SecurityElement.Escape(body)}</text>
            <text placement='attribution'>{System.Security.SecurityElement.Escape(appName)}</text>
        </binding>
    </visual>
</toast>";

            var doc = new XmlDocument();
            doc.LoadXml(xml);
            var toast = new ToastNotification(doc);
            ToastNotificationManager.CreateToastNotifier("Tether").Show(toast);
            toastShown = true;
        }
        catch { }

        if (!toastShown)
        {
            try
            {
                lock (_notifyLock)
                {
                    if (_fallbackNotifyIcon == null)
                    {
                        _fallbackNotifyIcon = new System.Windows.Forms.NotifyIcon
                        {
                            Icon = System.Drawing.SystemIcons.Information,
                            Visible = true
                        };
                    }
                    _fallbackNotifyIcon.ShowBalloonTip(4000, $"{appName}: {title}", body, System.Windows.Forms.ToolTipIcon.Info);
                }
            }
            catch { }
        }
    }

    private static NotificationPayload? ExtractNotificationPayload(UserNotification notif)
    {
        try
        {
            string app = notif.AppInfo?.DisplayInfo?.DisplayName ?? "Windows";
            if (string.Equals(app, "Tether", StringComparison.OrdinalIgnoreCase) ||
                app.StartsWith("Tether", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            string title = "";
            string body = "";

            var toastBinding = notif.Notification?.Visual?.GetBinding(KnownNotificationBindings.ToastGeneric);
            if (toastBinding != null)
            {
                var elements = toastBinding.GetTextElements();
                int idx = 0;
                foreach (var el in elements)
                {
                    if (idx == 0) title = el.Text;
                    else if (idx == 1) body = el.Text;
                    idx++;
                }
            }

            if (string.IsNullOrEmpty(title) && string.IsNullOrEmpty(body)) return null;

            return new NotificationPayload
            {
                Id = notif.Id,
                App = app,
                Title = title,
                Body = body,
                Timestamp = notif.CreationTime.ToUnixTimeMilliseconds()
            };
        }
        catch
        {
            return null;
        }
    }
}

public sealed class NotificationPayload
{
    public uint Id { get; set; }
    public string App { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Body { get; set; } = string.Empty;
    public long Timestamp { get; set; }
}
