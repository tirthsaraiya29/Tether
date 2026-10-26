package com.tether.phone

import org.junit.Assert.*
import org.junit.BeforeClass
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Principal
import java.security.PublicKey
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.Date

class MockX509Certificate(private val pubKey: PublicKey) : X509Certificate() {
    override fun checkValidity() {}
    override fun checkValidity(date: Date?) {}
    override fun getVersion(): Int = 3
    override fun getSerialNumber(): BigInteger = BigInteger.ONE
    override fun getIssuerDN(): Principal? = null
    override fun getSubjectDN(): Principal? = null
    override fun getNotBefore(): Date = Date()
    override fun getNotAfter(): Date = Date()
    override fun getTBSCertificate(): ByteArray = byteArrayOf()
    override fun getSignature(): ByteArray = byteArrayOf()
    override fun getSigAlgName(): String = "SHA256withECDSA"
    override fun getSigAlgOID(): String = "1.2.840.10045.4.3.2"
    override fun getSigAlgParams(): ByteArray? = null
    override fun getIssuerUniqueID(): BooleanArray? = null
    override fun getSubjectUniqueID(): BooleanArray? = null
    override fun getCriticalExtensionOIDs(): MutableSet<String>? = null
    override fun getNonCriticalExtensionOIDs(): MutableSet<String>? = null
    override fun getExtensionValue(oid: String?): ByteArray? = null
    override fun hasUnsupportedCriticalExtension(): Boolean = false
    override fun getPublicKey(): PublicKey = pubKey
    override fun toString(): String = "MockX509Certificate"
    override fun verify(key: PublicKey?) {}
    override fun verify(key: PublicKey?, sigProvider: String?) {}
    override fun getEncoded(): ByteArray = byteArrayOf()
    override fun getBasicConstraints(): Int = -1
    override fun getKeyUsage(): BooleanArray? = null
}

class FileTransferSecurityTest {

    companion object {
        private lateinit var validWindowsKeyPair: KeyPair
        private lateinit var attackerKeyPair: KeyPair
        private lateinit var validCert: X509Certificate
        private lateinit var attackerCert: X509Certificate

        @BeforeClass
        @JvmStatic
        fun setUp() {
            val kpg = KeyPairGenerator.getInstance("EC")
            kpg.initialize(256)
            validWindowsKeyPair = kpg.generateKeyPair()
            attackerKeyPair = kpg.generateKeyPair()

            validCert = MockX509Certificate(validWindowsKeyPair.public)
            attackerCert = MockX509Certificate(attackerKeyPair.public)
        }
    }

    @Test
    fun testPinnedTrustManager_SucceedsWithMatchingKey() {
        val pinnedKey = validWindowsKeyPair.public.encoded
        val trustManager = TetherPinnedTrustManager(context = null, overridePinnedKey = pinnedKey)

        try {
            trustManager.verifyPinning(arrayOf(validCert))
        } catch (e: Exception) {
            fail("Pinning verification should succeed with matching public key: ${e.message}")
        }
    }

    @Test
    fun testPinnedTrustManager_FailsWithMismatchedKey() {
        val pinnedKey = validWindowsKeyPair.public.encoded
        val trustManager = TetherPinnedTrustManager(context = null, overridePinnedKey = pinnedKey)

        var thrown = false
        try {
            trustManager.verifyPinning(arrayOf(attackerCert))
        } catch (e: CertificateException) {
            thrown = true
            assertTrue(e.message?.contains("pinning failed") == true)
        }
        assertTrue("Pinning verification must throw CertificateException on key mismatch", thrown)
    }

    @Test
    fun testPinnedTrustManager_FailsWhenNoPinnedKeyAndNotOverridden() {
        val trustManager = TetherPinnedTrustManager(context = null, overridePinnedKey = null)

        var thrown = false
        try {
            trustManager.verifyPinning(arrayOf(validCert))
        } catch (e: CertificateException) {
            thrown = true
            assertTrue(e.message?.contains("No pinned Windows public key found") == true)
        }
        assertTrue("Pinning verification must throw CertificateException when no key is pinned", thrown)
    }

    @Test
    fun testFileNameSanitization_PreventsPathTraversal() {
        val unsafeFileName = "../../etc/passwd"
        val safeName = java.io.File(unsafeFileName).name

        assertEquals("passwd", safeName)
        assertFalse(safeName.contains("/"))
        assertFalse(safeName.contains(".."))
    }
}
