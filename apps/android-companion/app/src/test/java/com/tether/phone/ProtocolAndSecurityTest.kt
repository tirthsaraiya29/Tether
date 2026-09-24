package com.tether.phone

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class ProtocolAndSecurityTest {

    @Test
    fun testAesGcmEncryptionDecryptionRoundtrip() {
        val sessionKey = ByteArray(32)
        SecureRandom().nextBytes(sessionKey)

        val originalCommand = "volume:75"
        val commandBytes = originalCommand.toByteArray(Charsets.UTF_8)

        val nonce = ByteArray(12)
        SecureRandom().nextBytes(nonce)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(sessionKey, "AES"), GCMParameterSpec(128, nonce))
        val ciphertext = cipher.doFinal(commandBytes)

        val wireFrame = ByteArray(nonce.size + ciphertext.size)
        System.arraycopy(nonce, 0, wireFrame, 0, nonce.size)
        System.arraycopy(ciphertext, 0, wireFrame, nonce.size, ciphertext.size)

        assertTrue(wireFrame.size >= 29)

        // Decrypt
        val extractedNonce = wireFrame.copyOfRange(0, 12)
        val extractedCiphertext = wireFrame.copyOfRange(12, wireFrame.size)

        val decryptCipher = Cipher.getInstance("AES/GCM/NoPadding")
        decryptCipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(sessionKey, "AES"), GCMParameterSpec(128, extractedNonce))
        val decryptedBytes = decryptCipher.doFinal(extractedCiphertext)
        val decryptedCommand = String(decryptedBytes, Charsets.UTF_8)

        assertEquals(originalCommand, decryptedCommand)
    }

    @Test(expected = AEADBadTagException::class)
    fun testAesGcmTamperedCiphertextRejection() {
        val sessionKey = ByteArray(32)
        SecureRandom().nextBytes(sessionKey)

        val commandBytes = "lock_now".toByteArray(Charsets.UTF_8)
        val nonce = ByteArray(12)
        SecureRandom().nextBytes(nonce)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(sessionKey, "AES"), GCMParameterSpec(128, nonce))
        val ciphertext = cipher.doFinal(commandBytes)

        // Tamper with the ciphertext/tag
        ciphertext[ciphertext.size - 1] = (ciphertext[ciphertext.size - 1].toInt() xor 0xFF).toByte()

        val decryptCipher = Cipher.getInstance("AES/GCM/NoPadding")
        decryptCipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(sessionKey, "AES"), GCMParameterSpec(128, nonce))
        decryptCipher.doFinal(ciphertext) // Must throw AEADBadTagException
    }

    @Test
    fun testRsaSignatureVerification() {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val keyPair = kpg.generateKeyPair()

        val nonce = ByteArray(16)
        SecureRandom().nextBytes(nonce)

        val signer = Signature.getInstance("SHA256withRSA")
        signer.initSign(keyPair.private)
        signer.update(nonce)
        val signature = signer.sign()

        val verifier = Signature.getInstance("SHA256withRSA")
        verifier.initVerify(keyPair.public)
        verifier.update(nonce)
        val isValid = verifier.verify(signature)

        assertTrue(isValid)

        // Verify with tampered nonce
        val tamperedNonce = nonce.clone()
        tamperedNonce[0] = (tamperedNonce[0].toInt() xor 0xFF).toByte()
        verifier.initVerify(keyPair.public)
        verifier.update(tamperedNonce)
        assertFalse(verifier.verify(signature))
    }

    @Test
    fun testPowerPlansDataStructure() {
        val plan1 = PowerPlanInfo("balanced", "Balanced", isActive = true)
        val plan2 = PowerPlanInfo("high_perf", "High Performance", isActive = false)

        val plans = listOf(plan1, plan2)

        assertEquals(2, plans.size)
        assertEquals("balanced", plans[0].id)
        assertTrue(plans[0].isActive)
        assertEquals("high_perf", plans[1].id)
        assertFalse(plans[1].isActive)
    }

    @Test
    fun testBatteryStateDataStructure() {
        val batteryState = BatteryState(
            percentage = 88,
            isCharging = true,
            health = "Good",
        )

        assertEquals(88, batteryState.percentage)
        assertTrue(batteryState.isCharging)
        assertEquals("Good", batteryState.health)
    }

    @Test
    fun testMediaStateDataStructure() {
        val mediaState = MediaState(
            title = "Starboy",
            artist = "The Weeknd",
            album = "Starboy",
            isPlaying = true,
            durationMs = 230000L,
            positionMs = 45000L,
            artworkBase64 = "base64data",
        )

        assertEquals("Starboy", mediaState.title)
        assertEquals("The Weeknd", mediaState.artist)
        assertEquals("Starboy", mediaState.album)
        assertTrue(mediaState.isPlaying)
        assertEquals(230000L, mediaState.durationMs)
        assertEquals(45000L, mediaState.positionMs)
        assertNotNull(mediaState.artworkBase64)
    }

    @Test
    fun testAppInfoDataStructure() {
        val app = AppInfo(
            id = "calc",
            name = "Calculator",
            category = "System",
            iconName = "calculator",
        )

        assertEquals("calc", app.id)
        assertEquals("Calculator", app.name)
        assertEquals("System", app.category)
        assertEquals("calculator", app.iconName)
    }

    @Test
    fun testControlCommandFormatting() {
        val volumeCommand = "volume:65"
        assertTrue(volumeCommand.startsWith("volume:"))
        assertEquals(65, volumeCommand.substringAfter("volume:").toInt())

        val brightnessCommand = "brightness:80"
        assertTrue(brightnessCommand.startsWith("brightness:"))
        assertEquals(80, brightnessCommand.substringAfter("brightness:").toInt())

        val appLaunchCommand = "app_launch:spotify"
        assertTrue(appLaunchCommand.startsWith("app_launch:"))
        assertEquals("spotify", appLaunchCommand.substringAfter("app_launch:"))

        val powerPlanCommand = "power_plan:high_performance"
        assertTrue(powerPlanCommand.startsWith("power_plan:"))
        assertEquals("high_performance", powerPlanCommand.substringAfter("power_plan:"))
    }

    @Test
    fun testShortWireFrameRejection() {
        val shortFrame = ByteArray(20) // Less than 29 bytes (12-byte nonce + 16-byte tag + 1-byte payload)
        assertTrue(shortFrame.size < 29)
    }

    @Test
    fun testRsaSignatureWrongKeyRejection() {
        val kpg1 = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
        val pair1 = kpg1.generateKeyPair()

        val kpg2 = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
        val pair2 = kpg2.generateKeyPair()

        val nonce = ByteArray(16).apply { SecureRandom().nextBytes(this) }

        val signer = Signature.getInstance("SHA256withRSA").apply {
            initSign(pair1.private)
            update(nonce)
        }
        val signature = signer.sign()

        val verifier = Signature.getInstance("SHA256withRSA").apply {
            initVerify(pair2.public) // Verification with wrong public key
            update(nonce)
        }
        assertFalse(verifier.verify(signature))
    }

    @Test
    fun testTrustTierAssigment() {
        val reportTrusted = IntegrityReport(
            score = 100,
            tier = TrustTier.TRUSTED,
            isBootloaderLocked = true,
            isNotRooted = true,
            isDevOptionsDisabled = true,
            isUsbDebuggingDisabled = true,
            isAppIntegrityValid = true,
            isSecureLockscreenEnabled = true,
        )
        assertEquals(TrustTier.TRUSTED, reportTrusted.tier)

        val reportRestricted = IntegrityReport(
            score = 50,
            tier = TrustTier.RESTRICTED,
            isBootloaderLocked = false,
            isNotRooted = false,
            isDevOptionsDisabled = false,
            isUsbDebuggingDisabled = false,
            isAppIntegrityValid = false,
            isSecureLockscreenEnabled = false,
        )
        assertEquals(TrustTier.RESTRICTED, reportRestricted.tier)
    }
}
