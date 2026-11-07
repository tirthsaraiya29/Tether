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
                    await NotifyCurrentMetadataAsync();
                };
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

                if (props.Thumbnail != null)
                {
                    try
                    {
                        using var stream = await props.Thumbnail.OpenReadAsync();
                        using var netStream = stream.AsStreamForRead();
                        using var ms = new MemoryStream();
                        await netStream.CopyToAsync(ms);
                        meta.ThumbnailBase64 = Convert.ToBase64String(ms.ToArray());
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
        try
        {
            if (_sessionManager == null)
            {
                _sessionManager = await GlobalSystemMediaTransportControlsSessionManager.RequestAsync();
            }

            var session = _sessionManager?.GetCurrentSession();
            if (session != null)
            {
                switch (action.ToLowerInvariant())
                {
                    case "play":
                        return await session.TryPlayAsync();
                    case "pause":
                        return await session.TryPauseAsync();
                    case "toggle":
                    case "play_pause":
                        return await session.TryTogglePlayPauseAsync();
                    case "next":
                        return await session.TrySkipNextAsync();
                    case "prev":
                    case "previous":
                        return await session.TrySkipPreviousAsync();
                    case "seek":
                        if (seekSeconds.HasValue)
                        {
                            return await session.TryChangePlaybackPositionAsync(seekSeconds.Value * 10_000_000L);
                        }
                        break;
                }
            }
        }
        catch { }

        // Fallback to virtual keyboard media events
        SendVirtualMediaKey(action);
        return true;
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
