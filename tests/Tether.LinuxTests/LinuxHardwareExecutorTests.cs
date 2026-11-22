using System;
using System.IO;
using Tether.LinuxDaemon.Capabilities;
using Tether.LinuxDaemon.Config;
using Tether.LinuxDaemon.Protocol;
using Tether.LinuxDaemon.Security;
using Tether.Shared.Logging;
using Xunit;

namespace Tether.LinuxTests;

public class LinuxHardwareExecutorTests
{
    private readonly ITetherLogger _logger = new SerilogTetherLogger();

    [Fact]
    public void TestGetBatteryInfo()
    {
        var (bat, charging) = LinuxLaptopStateCollector.GetBatteryInfo(_logger);

        // If battery exists in /sys/class/power_supply, it must be 0..100
        if (bat != -1)
        {
            Assert.InRange(bat, 0, 100);
        }
    }

    [Fact]
    public void TestGetLockState()
    {
        string lockState = LinuxLaptopStateCollector.GetLockState(_logger);
        Assert.NotNull(lockState);
        Assert.Contains(lockState, new[] { "LOCKED", "UNLOCKED", "UNKNOWN" });
    }

    [Fact]
    public void TestGetWallpaper()
    {
        string? path = LinuxLaptopStateCollector.DetectWallpaperPath(_logger);
        var (b64, hash) = LinuxLaptopStateCollector.GetWallpaperThumbnail(_logger);

        if (!string.IsNullOrEmpty(path) && File.Exists(path))
        {
            Assert.NotNull(b64);
            Assert.NotNull(hash);
            Assert.NotEmpty(b64);
            Assert.NotEmpty(hash);

            // Test caching
            var (b64Cached, hashCached) = LinuxLaptopStateCollector.GetWallpaperThumbnail(_logger);
            Assert.Equal(b64, b64Cached);
            Assert.Equal(hash, hashCached);
        }
    }

    [Fact]
    public void TestGetVolumeAndBrightness()
    {
        int vol = LinuxHardwareExecutor.GetSystemVolumeLevel(_logger);
        Assert.InRange(vol, 0, 100);

        int bri = LinuxHardwareExecutor.GetBrightnessLevel(_logger);
        Assert.InRange(bri, 0, 100);
    }

    [Fact]
    public void TestGetLaptopState()
    {
        LaptopStateFrame state = LinuxLaptopStateCollector.GetLaptopState(_logger);

        Assert.Equal("LAPTOP_STATE", state.Type);
        Assert.True(state.Timestamp > 0);
        Assert.InRange(state.VolumeLevel, 0, 100);
        Assert.InRange(state.BrightnessLevel, 0, 100);
    }

    [Fact]
    public void TestExecuteHardwareCommands()
    {
        string testDir = Path.Combine(Path.GetTempPath(), "tether_hw_test_" + Guid.NewGuid().ToString("N"));
        var config = new LinuxDaemonConfig
        {
            DataDir = testDir,
            RunDir = Path.Combine(testDir, "run"),
            LogDir = Path.Combine(testDir, "log"),
            PamSocketPath = Path.Combine(testDir, "run", "auth.sock")
        };
        Directory.CreateDirectory(config.RunDir);

        try
        {
            using var pamServer = new LinuxPamAuthServer(_logger, config);

            // Unrecognized command returns false
            bool invalid = LinuxHardwareExecutor.ExecuteCommand("some_invalid_cmd_123", _logger, pamServer, out _);
            Assert.False(invalid);

            // Unlock arms PAM grant
            bool unlock = LinuxHardwareExecutor.ExecuteCommand("unlock", _logger, pamServer, out _);
            Assert.True(unlock);

            // Set volume parse
            bool volSet = LinuxHardwareExecutor.ExecuteCommand("set_volume: 42", _logger, pamServer, out int curVol);
            if (volSet)
            {
                Assert.Equal(42, curVol);
            }
        }
        finally
        {
            try { Directory.Delete(testDir, true); } catch { }
        }
    }
}
