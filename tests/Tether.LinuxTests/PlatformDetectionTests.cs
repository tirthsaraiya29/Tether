using System;
using Tether.LinuxDaemon.Common;
using Xunit;

namespace Tether.LinuxTests;

public class PlatformDetectionTests
{
    [Fact]
    public void IsLinux_ReturnsExpectedPlatform()
    {
        bool expected = OperatingSystem.IsLinux();
        Assert.Equal(expected, PlatformDetection.IsLinux);
    }

    [Fact]
    public void GetDistributionName_ReturnsValidString()
    {
        string distro = PlatformDetection.GetDistributionName();
        Assert.False(string.IsNullOrWhiteSpace(distro));
        if (OperatingSystem.IsLinux())
        {
            Assert.DoesNotContain("Non-Linux", distro);
        }
        else
        {
            Assert.Equal("Non-Linux", distro);
        }
    }

    [Fact]
    public void GetActiveSessionInfo_ReturnsPopulatedSession()
    {
        var session = PlatformDetection.GetActiveSessionInfo();
        Assert.NotNull(session);
        Assert.False(string.IsNullOrWhiteSpace(session.UserName));
        Assert.True(session.Uid >= 0);
    }
}
