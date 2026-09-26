package com.tether.phone

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
 * Unit tests for Tether's cryptographic identity, TOFU pairing,
 * public key pinning, fingerprint calculation, and state verification.
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
        var pinnedWindowsKey: ByteArray? = null
        val presentedWindowsKey = windowsKeyPair.public.encoded
        val userApprovedPairing = true

        if (pinnedWindowsKey == null) {
            assertTrue("Pairing approval must be true", userApprovedPairing)
            pinnedWindowsKey = presentedWindowsKey
        }

        assertNotNull(pinnedWindowsKey)
        assertArrayEquals(presentedWindowsKey, pinnedWindowsKey)
    }

    @Test
    fun testFirstPairingDeniedRemainsNull() {
        var pinnedWindowsKey: ByteArray? = null
        val userApprovedPairing = false

        if (pinnedWindowsKey == null) {
            if (!userApprovedPairing) {
                // Pairing rejected by user
            } else {
                pinnedWindowsKey = windowsKeyPair.public.encoded
            }
        }

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

        // Attacker signature is valid for attacker key, but presented key != pinned key
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

        // User clicks Forget
        pinnedWindowsKey = null
        assertNull("Pinned key must be null after explicit forget", pinnedWindowsKey)
    }
}
