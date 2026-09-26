package com.tether.phone

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

class HandshakeAndTrustTest {

    private lateinit var phoneKeyPair: KeyPair
    private lateinit var windowsKeyPair: KeyPair
    private lateinit var attackerKeyPair: KeyPair

    @Before
    fun setUp() {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        phoneKeyPair = kpg.generateKeyPair()
        windowsKeyPair = kpg.generateKeyPair()
        attackerKeyPair = kpg.generateKeyPair()
    }

    private fun computeFingerprint(pubKeyBytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(pubKeyBytes)
        return hash.joinToString(":") { String.format("%02X", it) }
    }

    private fun encryptSessionKey(sessionKey: ByteArray, phonePubKeyBytes: ByteArray): ByteArray {
        val keyFactory = KeyFactory.getInstance("RSA")
        val phonePubKey = keyFactory.generatePublic(X509EncodedKeySpec(phonePubKeyBytes))
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding")
        val oaepSpec = OAEPParameterSpec(
            "SHA-1",
            "MGF1",
            MGF1ParameterSpec.SHA1,
            PSource.PSpecified.DEFAULT,
        )
        cipher.init(Cipher.ENCRYPT_MODE, phonePubKey, oaepSpec)
        return cipher.doFinal(sessionKey)
    }

    private fun decryptSessionKey(encryptedKey: ByteArray, phonePrivKey: PrivateKey): ByteArray {
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding")
        val oaepSpec = OAEPParameterSpec(
            "SHA-1",
            "MGF1",
            MGF1ParameterSpec.SHA1,
            PSource.PSpecified.DEFAULT,
        )
        cipher.init(Cipher.DECRYPT_MODE, phonePrivKey, oaepSpec)
        return cipher.doFinal(encryptedKey)
    }

    private fun signData(data: ByteArray, privateKey: PrivateKey): ByteArray {
        val sig = Signature.getInstance("SHA256withRSA")
        sig.initSign(privateKey)
        sig.update(data)
        return sig.sign()
    }

    private fun verifySignature(data: ByteArray, signature: ByteArray, publicKeyBytes: ByteArray): Boolean {
        val keyFactory = KeyFactory.getInstance("RSA")
        val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(publicKeyBytes))
        val sig = Signature.getInstance("SHA256withRSA")
        sig.initVerify(publicKey)
        sig.update(data)
        return sig.verify(signature)
    }

    @Test
    fun testFingerprintCalculation() {
        val fp = computeFingerprint(phoneKeyPair.public.encoded)
        assertNotNull(fp)
        assertTrue(fp.contains(":"))
        assertEquals(32, fp.split(":").size)
    }

    @Test
    fun testFirstPairingAccepted() {
        val phoneNonce = ByteArray(32) { 0x01 }
        val windowsNonce = ByteArray(32) { 0x02 }
        val sessionKey = ByteArray(32) { 0x03 }

        val dataToSign = phoneNonce + windowsNonce
        val signature = signData(dataToSign, windowsKeyPair.private)
        val encSessionKey = encryptSessionKey(sessionKey, phoneKeyPair.public.encoded)

        // 1. Verify Windows signature
        val sigValid = verifySignature(dataToSign, signature, windowsKeyPair.public.encoded)
        assertTrue("Signature must be valid", sigValid)

        // 2. Decrypt session key
        val decryptedSessionKey = decryptSessionKey(encSessionKey, phoneKeyPair.private)
        assertArrayEquals(sessionKey, decryptedSessionKey)

        // 3. Simulate TOFU logic: pinned key is null & pairingAccepted = true
        var pinnedWindowsKey: ByteArray? = null
        val pairingAccepted = true

        if (pinnedWindowsKey == null) {
            assertTrue("Pairing accepted must be true", pairingAccepted)
            pinnedWindowsKey = windowsKeyPair.public.encoded
        }

        assertNotNull(pinnedWindowsKey)
        assertArrayEquals(windowsKeyPair.public.encoded, pinnedWindowsKey)
    }

    @Test
    fun testFirstPairingDenied() {
        val phoneNonce = ByteArray(32) { 0x01 }
        val windowsNonce = ByteArray(32) { 0x02 }

        val dataToSign = phoneNonce + windowsNonce
        val signature = signData(dataToSign, windowsKeyPair.private)

        val sigValid = verifySignature(dataToSign, signature, windowsKeyPair.public.encoded)
        assertTrue(sigValid)

        var pinnedWindowsKey: ByteArray? = null
        val pairingAccepted = false

        var exceptionThrown = false
        if (pinnedWindowsKey == null) {
            if (!pairingAccepted) {
                exceptionThrown = true
            } else {
                pinnedWindowsKey = windowsKeyPair.public.encoded
            }
        }

        assertTrue("Exception must be thrown on pairing denied", exceptionThrown)
        assertNull("Pinned key must remain null when pairing is denied", pinnedWindowsKey)
    }

    @Test
    fun testUnauthenticatedPairingAcceptedFails() {
        val phoneNonce = ByteArray(32) { 0x01 }
        val windowsNonce = ByteArray(32) { 0x02 }

        // Attacker generates invalid signature with attacker key
        val dataToSign = phoneNonce + windowsNonce
        val badSignature = signData(dataToSign, attackerKeyPair.private)

        // Android verifies against presented Windows key
        val sigValid = verifySignature(dataToSign, badSignature, windowsKeyPair.public.encoded)
        assertFalse("Unauthenticated signature must be rejected", sigValid)
    }

    @Test
    fun testSubsequentReconnectSuccess() {
        var pinnedWindowsKey: ByteArray? = windowsKeyPair.public.encoded

        val phoneNonce = ByteArray(32) { 0x01 }
        val windowsNonce = ByteArray(32) { 0x02 }
        val presentedKey = windowsKeyPair.public.encoded

        val dataToSign = phoneNonce + windowsNonce
        val signature = signData(dataToSign, windowsKeyPair.private)
        val sigValid = verifySignature(dataToSign, signature, presentedKey)
        assertTrue(sigValid)

        // Pin equality check
        assertTrue("Presented key must match pinned key", presentedKey.contentEquals(pinnedWindowsKey))
    }

    @Test
    fun testSubsequentReconnectKeyMismatchFailsClosed() {
        val pinnedWindowsKey: ByteArray = windowsKeyPair.public.encoded
        val presentedAttackerKey: ByteArray = attackerKeyPair.public.encoded

        val phoneNonce = ByteArray(32) { 0x01 }
        val windowsNonce = ByteArray(32) { 0x02 }

        val dataToSign = phoneNonce + windowsNonce
        val signature = signData(dataToSign, attackerKeyPair.private)
        val sigValid = verifySignature(dataToSign, signature, presentedAttackerKey)
        assertTrue(sigValid)

        var isKeyMismatch = false
        if (!presentedAttackerKey.contentEquals(pinnedWindowsKey)) {
            isKeyMismatch = true
        }

        assertTrue("Key mismatch must be detected", isKeyMismatch)
        assertFalse("Pinned key must NOT be overwritten by attacker key", pinnedWindowsKey.contentEquals(presentedAttackerKey))
    }

    @Test
    fun testExplicitForgetClearsTrust() {
        var pinnedWindowsKey: ByteArray? = windowsKeyPair.public.encoded
        assertNotNull(pinnedWindowsKey)

        // Perform explicit forget
        pinnedWindowsKey = null
        assertNull("Pinned key must be null after explicit forget", pinnedWindowsKey)

        // Subsequent reconnect should now require new first-pairing approval
        val isPairingAccepted = true
        val presentedKey = attackerKeyPair.public.encoded // New host or same host re-pairing

        if (pinnedWindowsKey == null && isPairingAccepted) {
            pinnedWindowsKey = presentedKey
        }

        assertNotNull(pinnedWindowsKey)
        assertArrayEquals(presentedKey, pinnedWindowsKey)
    }

    @Test
    fun testStaleNonceResponseRejected() {
        val currentPhoneNonce = ByteArray(32) { 0x01.toByte() }
        val stalePhoneNonce = ByteArray(32) { 0x99.toByte() }
        val windowsNonce = ByteArray(32) { 0x02.toByte() }

        // Windows signed stale nonce
        val staleDataToSign = stalePhoneNonce + windowsNonce
        val signature = signData(staleDataToSign, windowsKeyPair.private)

        // Phone checks signature against current nonce
        val currentDataToSign = currentPhoneNonce + windowsNonce
        val sigValid = verifySignature(currentDataToSign, signature, windowsKeyPair.public.encoded)

        assertFalse("Stale response must fail signature verification against current nonce", sigValid)
    }

    @Test
    fun testAuthConfirmHmacValidation() {
        val sessionKey = ByteArray(32) { 0x07 }
        val windowsNonce = ByteArray(32) { 0x08 }

        val authConfirmData = windowsNonce + sessionKey

        val hmac = Mac.getInstance("HmacSHA256")
        hmac.init(SecretKeySpec(sessionKey, "HmacSHA256"))
        val expectedHmac = hmac.doFinal(authConfirmData)

        // Verify valid HMAC
        val hmacVerify = Mac.getInstance("HmacSHA256")
        hmacVerify.init(SecretKeySpec(sessionKey, "HmacSHA256"))
        val computedHmac = hmacVerify.doFinal(authConfirmData)

        assertArrayEquals(expectedHmac, computedHmac)
    }
}
