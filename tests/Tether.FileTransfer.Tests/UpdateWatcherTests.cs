using System;
using System.Collections.Generic;
using System.Text.Json;
using Tether.DesktopUI.Updates;
using Xunit;

namespace Tether.FileTransfer.Tests
{
    public class UpdateWatcherTests
    {
        [Theory]
        [InlineData("1.1.6", "1.1.7", true)]
        [InlineData("1.1.6", "1.1.6", false)]
        [InlineData("1.1.7", "1.1.6", false)]
        [InlineData("1.1.5", "1.2.0", true)]
        [InlineData("1.0.9", "1.1.0", true)]
        [InlineData("v1.1.6", "v1.1.7", true)]
        [InlineData("1.1.6", "v1.1.7", true)]
        [InlineData("v1.1.6", "1.1.6", false)]
        public void IsNewerVersion_CorrectlyComparesVersions(string local, string remote, bool expected)
        {
            bool actual = UpdateWatcherService.IsNewerVersion(local, remote);
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void UpdateEnvironment_DetectsSkipEnvVar()
        {
            Environment.SetEnvironmentVariable("TETHER_SKIP_UPDATES", "1");
            try
            {
                Assert.True(UpdateEnvironment.IsDebugOrDevEnvironment());
            }
            finally
            {
                Environment.SetEnvironmentVariable("TETHER_SKIP_UPDATES", null);
            }
        }

        [Fact]
        public void UpdateManifest_SerializesAndDeserializesCorrectly()
        {
            var manifest = new UpdateManifest
            {
                Version = "1.1.7",
                PublishedAt = DateTime.UtcNow.ToString("O"),
                Files = new List<ManifestFileEntry>
                {
                    new ManifestFileEntry
                    {
                        Path = "Tether.DesktopUI.dll",
                        Sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        Size = 98816,
                        IsService = false,
                        IsCredProv = false
                    },
                    new ManifestFileEntry
                    {
                        Path = "Tether.CommunicationService.exe",
                        Sha256 = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
                        Size = 238309490,
                        IsService = true,
                        IsCredProv = false
                    }
                }
            };

            string json = JsonSerializer.Serialize(manifest);
            var deserialized = JsonSerializer.Deserialize<UpdateManifest>(json);

            Assert.NotNull(deserialized);
            Assert.Equal("1.1.7", deserialized.Version);
            Assert.Equal(2, deserialized.Files.Count);
            Assert.Equal("Tether.DesktopUI.dll", deserialized.Files[0].Path);
            Assert.False(deserialized.Files[0].IsService);
            Assert.Equal("Tether.CommunicationService.exe", deserialized.Files[1].Path);
            Assert.True(deserialized.Files[1].IsService);
        }
    }
}
