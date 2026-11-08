using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Windows.Media.Control;
using Windows.Storage.Streams;

namespace Tether.SessionHelper;

internal sealed class MediaSessionController
{
    private const byte VK_MEDIA_NEXT_TRACK = 0xB0;
    private const byte VK_MEDIA_PREV_TRACK = 0xB1;
    private const byte VK_MEDIA_STOP = 0xB2;
    private const byte VK_MEDIA_PLAY_PAUSE = 0xB3;
    private const uint KEYEVENTF_KEYUP = 0x0002;

    [DllImport("user32.dll")]
    private static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);

    private static GlobalSystemMediaTransportControlsSessionManager? _sessionManager;
    private static Action<MediaMetadata>? _metadataChangedHandler;
    private static GlobalSystemMediaTransportControlsSession? _subscribedSession;

    private static string _cachedTitle = string.Empty;
    private static string _cachedAlbum = string.Empty;
    private static string _cachedThumbnailB64 = string.Empty;

    public static async Task InitializeAsync(Action<MediaMetadata> onMetadataChanged)
    {
        _metadataChangedHandler = onMetadataChanged;
        try
        {
            _sessionManager = await GlobalSystemMediaTransportControlsSessionManager.RequestAsync();
            if (_sessionManager != null)
            {
                _sessionManager.CurrentSessionChanged += async (s, e) =>
                {
                    HookCurrentSessionEvents();
                    await NotifyCurrentMetadataAsync();
                };
                HookCurrentSessionEvents();
            }
        }
        catch { }
    }

    private static void HookCurrentSessionEvents()
    {
        try
        {
            var session = _sessionManager?.GetCurrentSession();
            if (session != null && session != _subscribedSession)
            {
                _subscribedSession = session;
                session.MediaPropertiesChanged += async (s, e) => await NotifyCurrentMetadataAsync();
                session.PlaybackInfoChanged += async (s, e) => await NotifyCurrentMetadataAsync();
                session.TimelinePropertiesChanged += async (s, e) => await NotifyCurrentMetadataAsync();
            }
        }
        catch { }
    }

    public static async Task<MediaMetadata> GetCurrentMetadataAsync()
    {
        var meta = new MediaMetadata();
        try
        {
            if (_sessionManager == null)
            {
                _sessionManager = await GlobalSystemMediaTransportControlsSessionManager.RequestAsync();
            }

            var session = _sessionManager?.GetCurrentSession();
            if (session == null) return meta;

            var props = await session.TryGetMediaPropertiesAsync();
            if (props != null)
            {
                meta.Title = props.Title ?? "";
                meta.Artist = props.Artist ?? "";
                meta.Album = props.AlbumTitle ?? "";

                if (props.Title == _cachedTitle && props.AlbumTitle == _cachedAlbum && !string.IsNullOrEmpty(_cachedThumbnailB64))
                {
                    meta.ThumbnailBase64 = _cachedThumbnailB64;
                }
                else if (props.Thumbnail != null)
                {
                    try
                    {
                        using var stream = await props.Thumbnail.OpenReadAsync();
                        using var netStream = stream.AsStreamForRead();
                        using var ms = new MemoryStream();
                        await netStream.CopyToAsync(ms);
                        byte[] bytes = ms.ToArray();
                        if (bytes.Length > 0 && bytes.Length < 512 * 1024)
                        {
                            meta.ThumbnailBase64 = Convert.ToBase64String(bytes);
                            _cachedTitle = meta.Title;
                            _cachedAlbum = meta.Album;
                            _cachedThumbnailB64 = meta.ThumbnailBase64;
                        }
                    }
                    catch { }
                }
            }

            var playback = session.GetPlaybackInfo();
            if (playback != null)
            {
                meta.IsPlaying = playback.PlaybackStatus == GlobalSystemMediaTransportControlsSessionPlaybackStatus.Playing;
            }

            var timeline = session.GetTimelineProperties();
            if (timeline != null)
            {
                meta.PositionSeconds = (long)timeline.Position.TotalSeconds;
                meta.DurationSeconds = (long)(timeline.EndTime - timeline.StartTime).TotalSeconds;
            }
        }
        catch { }

        return meta;
    }

    public static async Task NotifyCurrentMetadataAsync()
    {
        var meta = await GetCurrentMetadataAsync();
        _metadataChangedHandler?.Invoke(meta);
    }

    public static async Task<bool> ExecuteMediaControlAsync(string action, long? seekSeconds = null)
    {
        string act = action.Trim().ToLowerInvariant();
        if (act == "get_metadata" || act == "refresh")
        {
            await NotifyCurrentMetadataAsync();
            return true;
        }

        bool handled = false;
        try
        {
            if (_sessionManager == null)
            {
                _sessionManager = await GlobalSystemMediaTransportControlsSessionManager.RequestAsync();
            }

            var session = _sessionManager?.GetCurrentSession();
            if (session != null)
            {
                switch (act)
                {
                    case "play":
                        handled = await session.TryPlayAsync();
                        break;
                    case "pause":
                        handled = await session.TryPauseAsync();
                        break;
                    case "toggle":
                    case "play_pause":
                        handled = await session.TryTogglePlayPauseAsync();
                        break;
                    case "next":
                        handled = await session.TrySkipNextAsync();
                        break;
                    case "prev":
                    case "previous":
                        handled = await session.TrySkipPreviousAsync();
                        break;
                    case "seek":
                        if (seekSeconds.HasValue)
                        {
                            handled = await session.TryChangePlaybackPositionAsync(seekSeconds.Value * 10_000_000L);
                        }
                        break;
                }
            }
        }
        catch { }

        if (!handled)
        {
            // Only send virtual media key if it is a standard transport action
            if (act is "play" or "pause" or "toggle" or "play_pause" or "next" or "prev" or "previous" or "stop")
            {
                SendVirtualMediaKey(act);
                handled = true;
            }
        }

        // Notify updated metadata shortly after command execution
        _ = Task.Delay(120).ContinueWith(async _ => await NotifyCurrentMetadataAsync());
        return handled;
    }

    private static void SendVirtualMediaKey(string action)
    {
        byte vk = action.ToLowerInvariant() switch
        {
            "next" => VK_MEDIA_NEXT_TRACK,
            "prev" or "previous" => VK_MEDIA_PREV_TRACK,
            "stop" => VK_MEDIA_STOP,
            _ => VK_MEDIA_PLAY_PAUSE
        };

        keybd_event(vk, 0, 0, UIntPtr.Zero);
        keybd_event(vk, 0, KEYEVENTF_KEYUP, UIntPtr.Zero);
    }
}

public sealed class MediaMetadata
{
    public string Title { get; set; } = string.Empty;
    public string Artist { get; set; } = string.Empty;
    public string Album { get; set; } = string.Empty;
    public bool IsPlaying { get; set; }
    public long PositionSeconds { get; set; }
    public long DurationSeconds { get; set; }
    public string ThumbnailBase64 { get; set; } = string.Empty;
}
