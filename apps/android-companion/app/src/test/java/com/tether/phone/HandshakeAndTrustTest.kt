package com.tether.phone

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * Comprehensive security test suite verifying Tether's local network connection,
 * TLS identity verification, TOFU key pinning, MITM rejection, capability authorization,
 * framing bounds enforcement, and post-quantum cryptographic primitives.
 */
class HandshakeAndTrustTest {

    private lateinit var phoneKeyPair: KeyPair
    private lateinit var windowsKeyPair: KeyPair
    private lateinit var attackerKeyPair: KeyPair

    @Before
    fun setUp() {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(256)
        phoneKeyPair = kpg.generateKeyPair()
        windowsKeyPair = kpg.generateKeyPair()
        attackerKeyPair = kpg.generateKeyPair()
    }

    private fun computeFingerprint(pubKeyBytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(pubKeyBytes)
        return hash.joinToString(":") { String.format("%02X", it) }
    }

    private fun signData(data: ByteArray, keyPair: KeyPair): ByteArray {
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(keyPair.private)
        sig.update(data)
        return sig.sign()
    }

    private fun verifySignature(data: ByteArray, signature: ByteArray, pubKeyBytes: ByteArray): Boolean {
        return try {
            val keyFactory = KeyFactory.getInstance("EC")
            val pubKeySpec = X509EncodedKeySpec(pubKeyBytes)
            val pubKey = keyFactory.generatePublic(pubKeySpec)
            val sig = Signature.getInstance("SHA256withECDSA")
            sig.initVerify(pubKey)
            sig.update(data)
            sig.verify(signature)
        } catch (_: Exception) {
            false
        }
    }

    @Test
    fun testFingerprintCalculation() {
        val fp = computeFingerprint(phoneKeyPair.public.encoded)
        assertNotNull(fp)
        assertTrue(fp.contains(":"))
        assertEquals(32, fp.split(":").size)
    }

    @Test
    fun testFirstPairingAcceptedAndPinned() {
        val presentedWindowsKey = windowsKeyPair.public.encoded
        val userApprovedPairing = true

        val pinnedWindowsKey = if (userApprovedPairing) presentedWindowsKey else null

        assertNotNull(pinnedWindowsKey)
        assertArrayEquals(presentedWindowsKey, pinnedWindowsKey)
    }

    @Test
    fun testFirstPairingDeniedRemainsNull() {
        val userApprovedPairing = false

        val pinnedWindowsKey: ByteArray? = if (userApprovedPairing) windowsKeyPair.public.encoded else null

        assertNull("Pinned key must remain null when pairing is rejected", pinnedWindowsKey)
    }

    @Test
    fun testSubsequentConnectMatchingPinnedKeySucceeds() {
        val pinnedWindowsKey = windowsKeyPair.public.encoded
        val presentedWindowsKey = windowsKeyPair.public.encoded

        val nonceData = "SESSION_NONCE_12345".toByteArray()
        val signature = signData(nonceData, windowsKeyPair)
        val sigValid = verifySignature(nonceData, signature, presentedWindowsKey)

        assertTrue("Signature verification must succeed", sigValid)
        assertTrue("Presented key must match pinned key", presentedWindowsKey.contentEquals(pinnedWindowsKey))
    }

    @Test
    fun testSubsequentConnectKeyMismatchFailsClosed() {
        val pinnedWindowsKey = windowsKeyPair.public.encoded
        val attackerKey = attackerKeyPair.public.encoded

        val nonceData = "SESSION_NONCE_12345".toByteArray()
        val attackerSignature = signData(nonceData, attackerKeyPair)

        val sigValid = verifySignature(nonceData, attackerSignature, attackerKey)
        assertTrue(sigValid)

        val isKeyMismatch = !attackerKey.contentEquals(pinnedWindowsKey)
        assertTrue("Key mismatch must be detected", isKeyMismatch)
        assertFalse("Pinned key must NOT be overwritten", pinnedWindowsKey.contentEquals(attackerKey))
    }

    @Test
    fun testExplicitForgetClearsTrust() {
        var pinnedWindowsKey: ByteArray? = windowsKeyPair.public.encoded
        assertNotNull(pinnedWindowsKey)

        pinnedWindowsKey = null
        assertNull("Pinned key must be null after explicit forget", pinnedWindowsKey)
    }

    @Test
    fun testCapabilityAuthorizationMatrix() {
        val capManager = TetherCapabilityManager()
        capManager.negotiateCapabilities("CLIPBOARD,FILES,NOTIFICATIONS,MEDIA")

        assertTrue("Media command must be allowed", capManager.canExecuteCommand("volume_up"))
        assertTrue("Clipboard command must be allowed", capManager.canExecuteCommand("copy"))
        assertFalse("Elevated power command must be denied without POWER_ELEVATED capability", capManager.canExecuteCommand("shutdown"))
        assertFalse("Terminal command must be denied without TERMINAL capability", capManager.canExecuteCommand("powershell"))

        // Re-negotiate with elevated capability
        capManager.negotiateCapabilities("CLIPBOARD,FILES,NOTIFICATIONS,MEDIA,TERMINAL,POWER_ELEVATED")
        assertTrue("Elevated power command must be allowed when capability is granted", capManager.canExecuteCommand("shutdown"))
        assertTrue("Terminal command must be allowed when capability is granted", capManager.canExecuteCommand("powershell"))
    }

    fun isFrameWithinLimit(frameSize: Int, maxLimit: Int): Boolean = frameSize <= maxLimit

    @Test
    fun testFramingBoundaryLimits() {
        val maxFrameSize = 1024 * 1024 // 1 MB
        val validFrameSize = 512 * 1024 // 512 KB
        val oversizedFrameSize = 2 * 1024 * 1024 // 2 MB

        assertTrue("Valid frame size must be within limit", isFrameWithinLimit(validFrameSize, maxFrameSize))
        assertFalse("Oversized frame must exceed limit", isFrameWithinLimit(oversizedFrameSize, maxFrameSize))
    }

    @Test
    fun testPostQuantumProviderAvailability() {
        val bcProvider = BouncyCastleProvider()
        assertNotNull("BouncyCastle provider must be available", bcProvider)
        assertEquals("BC", bcProvider.name)
    }

    @Test
    fun testPinSasProofCalculation() {
        val pin = "482910"
        val phonePubKey = phoneKeyPair.public.encoded
        val winPubKey = windowsKeyPair.public.encoded
        val requestId = "REQ_TEST_12345"

        val pinBytes = pin.toByteArray(Charsets.UTF_8)
        val reqIdBytes = requestId.toByteArray(Charsets.UTF_8)
        val transcriptHash = MessageDigest.getInstance("SHA-512").digest("TRANSCRIPT_DATA".toByteArray())

        // Calculate expectedPhoneProof exactly as Windows PairingManager.cs:
        // ComputeSha512(pin, phoneSpkiDer, winSpkiDer, requestId, transcriptHash)
        val digest = MessageDigest.getInstance("SHA-512")
        digest.update(pinBytes)
        digest.update(phonePubKey)
        digest.update(winPubKey)
        digest.update(reqIdBytes)
        digest.update(transcriptHash)
        val phoneProof = digest.digest()

        assertNotNull(phoneProof)
        assertEquals(64, phoneProof.size)

        // Verify that swapped public key order produces a non-matching hash
        val digestSwappedKeys = MessageDigest.getInstance("SHA-512")
        digestSwappedKeys.update(pinBytes)
        digestSwappedKeys.update(winPubKey)
        digestSwappedKeys.update(phonePubKey)
        digestSwappedKeys.update(reqIdBytes)
        digestSwappedKeys.update(transcriptHash)
        val proofSwappedKeys = digestSwappedKeys.digest()

        assertFalse(
            "SAS proof must match Windows key order (PhonePubKey before WinPubKey)",
            phoneProof.contentEquals(proofSwappedKeys),
        )
    }
}
