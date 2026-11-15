using System.Text.RegularExpressions;
using Xunit;

namespace Tether.Tests;

public class HandshakeDeviceIdValidationTests
{
    private static readonly Regex DeviceIdRegex = new(@"^[a-zA-Z0-9_\-\.:]{1,128}$", RegexOptions.Compiled);

    [Theory]
    [InlineData("07:C7:54:7F:E2:1D:6D:48:16:0E:EB:8B:7F:AC:9B:5A:2B:7A:94:4C:A9:2D:D0:61:E4:7B:DE:68:8B:47:9F:58")] // SHA256 with colons (95 chars)
    [InlineData("07c7547fe21d6d48160eeb8b7fac9b5a2b7a944ca92dd061e47bde688b479f58")] // Raw hex fingerprint (64 chars)
    [InlineData("e8869843-1234-5678-9abc-def012345678")] // Standard GUID (36 chars)
    [InlineData("Tether_Pixel_9_Pro.node-1")] // Alphanumeric with dots, dashes, underscores
    [InlineData("android-device-123")]
    public void ValidDeviceIdFormats_AreAccepted(string deviceId)
    {
        Assert.Matches(DeviceIdRegex, deviceId);
    }

    [Theory]
    [InlineData("device; rm -rf /")]
    [InlineData("device<script>alert(1)</script>")]
    [InlineData("../../../etc/passwd")]
    [InlineData("device\0nullbyte")]
    [InlineData("device\nnewline")]
    [InlineData("device\rreturn")]
    [InlineData("device\"quote")]
    [InlineData("device'quote")]
    [InlineData("device/with/slashes")]
    [InlineData("device\\with\\backslashes")]
    public void MaliciousOrInvalidDeviceIdFormats_AreRejected(string deviceId)
    {
        Assert.DoesNotMatch(DeviceIdRegex, deviceId);
    }

    [Fact]
    public void ExcessiveLengthDeviceId_IsRejected()
    {
        string oversized = new string('a', 129);
        Assert.DoesNotMatch(DeviceIdRegex, oversized);
    }
}
