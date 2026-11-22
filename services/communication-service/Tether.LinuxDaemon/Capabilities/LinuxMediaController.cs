using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using Tether.LinuxDaemon.Common;
using Tether.Shared.Logging;

namespace Tether.LinuxDaemon.Capabilities;

public sealed record LinuxMediaMetadata
{
    public string Title { get; init; } = "";
    public string Artist { get; init; } = "";
    public string Album { get; init; } = "";
    public bool IsPlaying { get; init; }
    public long PositionSeconds { get; init; }
    public long DurationSeconds { get; init; }
    public string? ThumbnailBase64 { get; init; }
}

public static class LinuxMediaController
{
    public static async Task<bool> ExecuteMediaControlAsync(string action, long? seekSec, ITetherLogger logger)
    {
        if (string.IsNullOrWhiteSpace(action)) return false;
        string act = action.Trim().ToLowerInvariant();

        string playerctlCmd = act switch
        {
            "play" => "play",
            "pause" => "pause",
            "play_pause" or "toggle" or "playpause" => "play-pause",
            "next" => "next",
            "previous" or "prev" => "previous",
            "stop" => "stop",
            _ => ""
        };

        if (seekSec.HasValue && act == "seek")
        {
            return await RunPlayerctlAsync($"position {seekSec.Value}", logger);
        }

        if (!string.IsNullOrEmpty(playerctlCmd))
        {
            return await RunPlayerctlAsync(playerctlCmd, logger);
        }

        return false;
    }

    public static async Task<LinuxMediaMetadata> GetCurrentMetadataAsync(ITetherLogger logger)
    {
        try
        {
            // Format: Title||Artist||Album||Status||Position||Length||ArtUrl
            var session = PlatformDetection.GetActiveSessionInfo();
            string uidStr = session.Uid > 0 ? session.Uid.ToString() : "1000";
            string busAddr = $"unix:path=/run/user/{uidStr}/bus";

            var psi = new ProcessStartInfo
            {
                FileName = "playerctl",
                Arguments = "metadata --format '{{title}}||{{artist}}||{{album}}||{{status}}||{{position}}||{{mpris:length}}||{{mpris:artUrl}}'",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            psi.EnvironmentVariables["DBUS_SESSION_BUS_ADDRESS"] = busAddr;

            using var p = Process.Start(psi);
            if (p != null)
            {
                string output = await p.StandardOutput.ReadToEndAsync();
                await p.WaitForExitAsync();
                output = output.Trim('\'', '\"', ' ', '\r', '\n');

                if (!string.IsNullOrEmpty(output) && output.Contains("||"))
                {
                    string[] parts = output.Split("||");
                    string title = parts.Length > 0 ? parts[0] : "";
                    string artist = parts.Length > 1 ? parts[1] : "";
                    string album = parts.Length > 2 ? parts[2] : "";
                    string status = parts.Length > 3 ? parts[3] : "";
                    bool isPlaying = status.Equals("Playing", StringComparison.OrdinalIgnoreCase);

                    long pos = 0;
                    if (parts.Length > 4 && double.TryParse(parts[4], System.Globalization.CultureInfo.InvariantCulture, out double posMicros))
                    {
                        pos = (long)(posMicros / 1_000_000.0);
                    }

                    long dur = 0;
                    if (parts.Length > 5 && double.TryParse(parts[5], System.Globalization.CultureInfo.InvariantCulture, out double durMicros))
                    {
                        dur = (long)(durMicros / 1_000_000.0);
                    }

                    string? artUrl = parts.Length > 6 ? parts[6] : null;
                    string? thumbB64 = null;
                    if (!string.IsNullOrEmpty(artUrl) && artUrl.StartsWith("file://", StringComparison.OrdinalIgnoreCase))
                    {
                        string localPath = Uri.UnescapeDataString(artUrl.Substring(7));
                        if (File.Exists(localPath) && new FileInfo(localPath).Length <= 1_000_000)
                        {
                            thumbB64 = Convert.ToBase64String(await File.ReadAllBytesAsync(localPath));
                        }
                    }

                    return new LinuxMediaMetadata
                    {
                        Title = title,
                        Artist = artist,
                        Album = album,
                        IsPlaying = isPlaying,
                        PositionSeconds = pos,
                        DurationSeconds = dur,
                        ThumbnailBase64 = thumbB64
                    };
                }
            }
        }
        catch (Exception ex)
        {
            logger.Debug($"LinuxMediaController: Metadata query failed: {ex.Message}");
        }

        return new LinuxMediaMetadata();
    }

    private static async Task<bool> RunPlayerctlAsync(string args, ITetherLogger logger)
    {
        try
        {
            var session = PlatformDetection.GetActiveSessionInfo();
            string uidStr = session.Uid > 0 ? session.Uid.ToString() : "1000";
            string busAddr = $"unix:path=/run/user/{uidStr}/bus";

            var psi = new ProcessStartInfo
            {
                FileName = "playerctl",
                Arguments = args,
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
            logger.Warning($"LinuxMediaController: playerctl {args} error: {ex.Message}");
        }
        return false;
    }
}
