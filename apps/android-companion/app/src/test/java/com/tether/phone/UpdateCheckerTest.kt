package com.tether.phone
import org.junit.Assert.*
import org.junit.Test
class UpdateCheckerTest {
    @Test
    fun testIsNewerVersionComparison() {
        assertTrue(UpdateChecker.isNewerVersion("1.0.0", "1.0.1"))
        assertTrue(UpdateChecker.isNewerVersion("1.0.0", "1.1.0"))
        assertTrue(UpdateChecker.isNewerVersion("1.0.0", "2.0.0"))
        assertTrue(UpdateChecker.isNewerVersion("v1.0.0", "v1.0.1"))
        assertFalse(UpdateChecker.isNewerVersion("1.0.1", "1.0.0"))
        assertFalse(UpdateChecker.isNewerVersion("1.0.0", "1.0.0"))
        assertFalse(UpdateChecker.isNewerVersion("2.0.0", "1.9.9"))
        assertFalse(UpdateChecker.isNewerVersion("v1.2.0", "v1.2.0"))
    }
    @Test
    fun testUpdateInfoDataClass() {
        val info = UpdateInfo(
            latestVersion = "1.2.3",
            releaseUrl = "https://github.com/tirthsaraiya29/Tether/releases/tag/v1.2.3",
            releaseNotes = "New features",
            apkDownloadUrl = "https://github.com/tirthsaraiya29/Tether/releases/download/v1.2.3/app.apk"
        )
        assertEquals("1.2.3", info.latestVersion)
        assertEquals("https://github.com/tirthsaraiya29/Tether/releases/tag/v1.2.3", info.releaseUrl)
        assertEquals("New features", info.releaseNotes)
        assertEquals("https://github.com/tirthsaraiya29/Tether/releases/download/v1.2.3/app.apk", info.apkDownloadUrl)
    }
}
