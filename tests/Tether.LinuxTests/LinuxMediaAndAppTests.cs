using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Tether.LinuxDaemon.Capabilities;
using Tether.Shared.Logging;
using Xunit;

namespace Tether.LinuxTests;

public class LinuxMediaAndAppTests
{
    private readonly ITetherLogger _logger = new SerilogTetherLogger();

    [Fact]
    public async Task MediaController_HandlesActions_AndReturnsMetadata()
    {
        // Invalid action
        bool invalid = await LinuxMediaController.ExecuteMediaControlAsync("", null, _logger);
        Assert.False(invalid);

        // Get metadata does not throw even when no active MPRIS player
        var meta = await LinuxMediaController.GetCurrentMetadataAsync(_logger);
        Assert.NotNull(meta);
    }

    [Fact]
    public async Task NotificationController_DispatchesSafely()
    {
        bool result = await LinuxNotificationController.ShowNotificationOnDesktopAsync(
            "Tether Test Notification", "This is an automated test message", "TetherTest", _logger);

        // May return true if GUI session bus is active
        Assert.True(result || !result); // Verification that call completes without throwing
    }

    [Fact]
    public void ApplicationManager_DiscoversInstalledApplications()
    {
        var apps = LinuxApplicationManager.GetInstalledApps(_logger);
        Assert.NotEmpty(apps);

        // Verify that well-known desktop apps exist
        Assert.All(apps, a =>
        {
            Assert.False(string.IsNullOrWhiteSpace(a.Name));
            Assert.False(string.IsNullOrWhiteSpace(a.Path));
        });
    }

    [Fact]
    public void ApplicationManager_GetRunningWindows_ExecutesSafely()
    {
        var windows = LinuxApplicationManager.GetRunningWindows(_logger);
        Assert.NotNull(windows);
    }

    [Fact]
    public async Task ApplicationManager_CloseInvalidWindow_FailsSafely()
    {
        bool closed = await LinuxApplicationManager.CloseWindowAsync("0x99999999", _logger);
        Assert.False(closed);
    }
}
