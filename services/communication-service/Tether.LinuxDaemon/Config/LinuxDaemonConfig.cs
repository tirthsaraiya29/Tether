using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using Tether.Shared.Network;

namespace Tether.LinuxDaemon.Config;

public sealed class LinuxDaemonConfig
{
    public const string DefaultSystemConfigPath = "/etc/tether/tether.conf";
    public const string DefaultSystemDataDir = "/var/lib/tether";
    public const string DefaultSystemRunDir = "/run/tether";
    public const string DefaultSystemLogDir = "/var/log/tether";

    [JsonPropertyName("controlPort")]
    public int ControlPort { get; set; } = NetworkConstants.ControlPort;

    [JsonPropertyName("discoveryPort")]
    public int DiscoveryPort { get; set; } = NetworkConstants.DiscoveryPort;

    [JsonPropertyName("fileTransferPort")]
    public int FileTransferPort { get; set; } = NetworkConstants.FileTransferPort;

    [JsonPropertyName("dataDir")]
    public string DataDir { get; set; } = DefaultSystemDataDir;

    [JsonPropertyName("runDir")]
    public string RunDir { get; set; } = DefaultSystemRunDir;

    [JsonPropertyName("logDir")]
    public string LogDir { get; set; } = DefaultSystemLogDir;

    [JsonPropertyName("pamSocketPath")]
    public string PamSocketPath { get; set; } = Path.Combine(DefaultSystemRunDir, "auth.sock");

    [JsonPropertyName("allowPairing")]
    public bool AllowPairing { get; set; } = true;

    [JsonPropertyName("requireBiometrics")]
    public bool RequireBiometrics { get; set; } = true;

    [JsonPropertyName("autoStartSessionHelper")]
    public bool AutoStartSessionHelper { get; set; } = true;

    public static LinuxDaemonConfig Load(string? customPath = null)
    {
        string path = customPath ?? (File.Exists(DefaultSystemConfigPath)
            ? DefaultSystemConfigPath
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config", "tether", "tether.conf"));

        if (File.Exists(path))
        {
            try
            {
                string json = File.ReadAllText(path);
                var loaded = JsonSerializer.Deserialize<LinuxDaemonConfig>(json);
                if (loaded != null) return loaded;
            }
            catch { }
        }

        // Return default configuration, adapted if running unprivileged as standard user
        var cfg = new LinuxDaemonConfig();
        if (Environment.GetEnvironmentVariable("USER") != "root" && !File.Exists(DefaultSystemConfigPath))
        {
            string userHome = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            cfg.DataDir = Path.Combine(userHome, ".local", "share", "tether");
            cfg.RunDir = Path.Combine(userHome, ".local", "run", "tether");
            cfg.LogDir = Path.Combine(userHome, ".local", "state", "tether");
            cfg.PamSocketPath = Path.Combine(cfg.RunDir, "auth.sock");
        }

        return cfg;
    }

    public void EnsureDirectories()
    {
        Directory.CreateDirectory(DataDir);
        Directory.CreateDirectory(RunDir);
        Directory.CreateDirectory(LogDir);

        if (OperatingSystem.IsLinux())
        {
            try
            {
                File.SetUnixFileMode(DataDir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                File.SetUnixFileMode(RunDir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                                             UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
                                             UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
            }
            catch { }
        }
    }
}
