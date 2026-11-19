using System;
using System.Windows.Media;

namespace Tether.DesktopUI;

public enum NotificationType
{
    Info,
    Success,
    Warning,
    Error
}

public class DesktopNotification
{
    public Guid Id { get; } = Guid.NewGuid();
    public string Title { get; }
    public string Message { get; }
    public DateTime Timestamp { get; } = DateTime.Now;
    public NotificationType Type { get; }

    public string FormattedTime => Timestamp.ToString("HH:mm:ss");

    public string Icon => Type switch
    {
        NotificationType.Success => "\uE73E",
        NotificationType.Warning => "\uE7BA",
        NotificationType.Error => "\uEA39",
        _ => "\uE946"
    };

    public Brush AccentBrush => Type switch
    {
        NotificationType.Success => _successBrush,
        NotificationType.Warning => _warningBrush,
        NotificationType.Error => _errorBrush,
        _ => _accentBrush
    };

    public Brush BadgeBackgroundBrush => Type switch
    {
        NotificationType.Success => _successBadgeBg,
        NotificationType.Warning => _warningBadgeBg,
        NotificationType.Error => _errorBadgeBg,
        _ => _accentBadgeBg
    };

    public Brush BorderBrush => Type switch
    {
        NotificationType.Success => _successBorder,
        NotificationType.Warning => _warningBorder,
        NotificationType.Error => _errorBorder,
        _ => _accentBorder
    };

    public Brush BackgroundBrush => _cardBg;

    private static readonly SolidColorBrush _cardBg = CreateFrozenBrush(Color.FromArgb(0xEE, 0x0D, 0x12, 0x1B));
    private static readonly SolidColorBrush _accentBrush = CreateFrozenBrush(Color.FromRgb(0x38, 0xBD, 0xF8));
    private static readonly SolidColorBrush _accentBadgeBg = CreateFrozenBrush(Color.FromArgb(0x22, 0x38, 0xBD, 0xF8));
    private static readonly SolidColorBrush _accentBorder = CreateFrozenBrush(Color.FromArgb(0x40, 0x38, 0xBD, 0xF8));

    private static readonly SolidColorBrush _successBrush = CreateFrozenBrush(Color.FromRgb(0x10, 0xB9, 0x81));
    private static readonly SolidColorBrush _successBadgeBg = CreateFrozenBrush(Color.FromArgb(0x22, 0x10, 0xB9, 0x81));
    private static readonly SolidColorBrush _successBorder = CreateFrozenBrush(Color.FromArgb(0x40, 0x10, 0xB9, 0x81));

    private static readonly SolidColorBrush _warningBrush = CreateFrozenBrush(Color.FromRgb(0xF5, 0x9E, 0x0B));
    private static readonly SolidColorBrush _warningBadgeBg = CreateFrozenBrush(Color.FromArgb(0x22, 0xF5, 0x9E, 0x0B));
    private static readonly SolidColorBrush _warningBorder = CreateFrozenBrush(Color.FromArgb(0x40, 0xF5, 0x9E, 0x0B));

    private static readonly SolidColorBrush _errorBrush = CreateFrozenBrush(Color.FromRgb(0xF4, 0x3F, 0x5E));
    private static readonly SolidColorBrush _errorBadgeBg = CreateFrozenBrush(Color.FromArgb(0x22, 0xF4, 0x3F, 0x5E));
    private static readonly SolidColorBrush _errorBorder = CreateFrozenBrush(Color.FromArgb(0x40, 0xF4, 0x3F, 0x5E));

    private static SolidColorBrush CreateFrozenBrush(Color c)
    {
        var b = new SolidColorBrush(c);
        b.Freeze();
        return b;
    }

    public DesktopNotification(string title, string message, NotificationType type = NotificationType.Info)
    {
        Title = title;
        Message = message;
        Type = type;
    }
}
