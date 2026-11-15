package com.tether.phone

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Principal
import java.security.PublicKey
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.Date

class TetherTransportTrustManagerTest {

    private class TestX509Certificate(
        private val pubKey: PublicKey,
        private val isValid: Boolean = true
    ) : X509Certificate() {
        override fun getPublicKey(): PublicKey = pubKey
        override fun checkValidity() {
            if (!isValid) throw CertificateException("Certificate expired or invalid")
        }
        override fun checkValidity(date: Date?) {
            if (!isValid) throw CertificateException("Certificate expired or invalid")
        }
        override fun getEncoded(): ByteArray = pubKey.encoded
        override fun verify(key: PublicKey?) {}
        override fun verify(key: PublicKey?, sigProvider: String?) {}
        override fun toString(): String = "TestX509Certificate"
        override fun getVersion(): Int = 3
        override fun getSerialNumber(): BigInteger = BigInteger.ONE
        override fun getIssuerDN(): Principal = Principal { "CN=Test" }
        override fun getSubjectDN(): Principal = Principal { "CN=Test" }
        override fun getNotBefore(): Date = Date(System.currentTimeMillis() - 10000)
        override fun getNotAfter(): Date = Date(System.currentTimeMillis() + 10000)
        override fun getSigAlgName(): String = "SHA256withECDSA"
        override fun getSigAlgOID(): String = "1.2.840.10045.4.3.2"
        override fun getSigAlgParams(): ByteArray? = null
        override fun getIssuerUniqueID(): BooleanArray? = null
        override fun getSubjectUniqueID(): BooleanArray? = null
        override fun getKeyUsage(): BooleanArray? = null
        override fun getBasicConstraints(): Int = -1
        override fun getTBSCertificate(): ByteArray = byteArrayOf()
        override fun getSignature(): ByteArray = byteArrayOf()
        override fun hasUnsupportedCriticalExtension(): Boolean = false
        override fun getCriticalExtensionOIDs(): Set<String>? = null
        override fun getNonCriticalExtensionOIDs(): Set<String>? = null
        override fun getExtensionValue(oid: String?): ByteArray? = null
    }

    private val kpg = KeyPairGenerator.getInstance("EC").apply { initialize(256) }
    private val keyPair1 = kpg.generateKeyPair()
    private val keyPair2 = kpg.generateKeyPair()

    @Test
    fun testRejectNullOrEmptyChain() {
        val tm = TetherTransportTrustManager(
            context = null,
            securityEngine = ProductionSecurityEngine(),
            expectedPeerFingerprint = "test-fp"
        )

        assertThrows(CertificateException::class.java) {
            tm.verifyCertificate(null)
        }
        assertThrows(CertificateException::class.java) {
            tm.verifyCertificate(emptyArray())
        }
    }

    @Test
    fun testValidateAgainstPinnedKey_SuccessAndMismatch() {
        val cert = TestX509Certificate(keyPair1.public)
        val tmMatch = TetherTransportTrustManager(
            context = null,
            securityEngine = ProductionSecurityEngine(),
            expectedPeerPublicKey = keyPair1.public.encoded
        )

        // Must succeed without throwing
        tmMatch.verifyCertificate(arrayOf(cert))
        assertEquals(cert, tmMatch.acceptedIssuers.firstOrNull())

        // Mismatched pinned key must throw CertificateException
        val tmMismatch = TetherTransportTrustManager(
            context = null,
            securityEngine = ProductionSecurityEngine(),
            expectedPeerPublicKey = keyPair2.public.encoded
        )
        assertThrows(CertificateException::class.java) {
            tmMismatch.verifyCertificate(arrayOf(cert))
        }
    }

    @Test
    fun testValidateAgainstDiscoveredFingerprint_SuccessAndMismatch() {
        val cert = TestX509Certificate(keyPair1.public)
        val engine = ProductionSecurityEngine()
        val correctFp = engine.computePublicKeyFingerprint(keyPair1.public.encoded)

        val tmMatch = TetherTransportTrustManager(
            context = null,
            securityEngine = engine,
            expectedPeerFingerprint = correctFp
        )
        tmMatch.verifyCertificate(arrayOf(cert))
        assertEquals(cert, tmMatch.acceptedIssuers.firstOrNull())

        val tmMismatch = TetherTransportTrustManager(
            context = null,
            securityEngine = engine,
            expectedPeerFingerprint = "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF"
        )
        assertThrows(CertificateException::class.java) {
            tmMismatch.verifyCertificate(arrayOf(cert))
        }
    }

    @Test
    fun testRejectWhenUnpinnedAndNoDiscoveredFingerprint() {
        val cert = TestX509Certificate(keyPair1.public)
        val tmUnpinned = TetherTransportTrustManager(
            context = null,
            securityEngine = ProductionSecurityEngine(),
            expectedPeerFingerprint = null,
            expectedPeerPublicKey = null
        )

        val ex = assertThrows(CertificateException::class.java) {
            tmUnpinned.verifyCertificate(arrayOf(cert))
        }
        assertTrue(ex.message!!.contains("Refusing connection"))
    }

    @Test
    fun testRejectClientCertificates() {
        val tm = TetherTransportTrustManager(
            context = null,
            securityEngine = ProductionSecurityEngine()
        )
        assertThrows(CertificateException::class.java) {
            tm.checkClientTrusted(arrayOf(TestX509Certificate(keyPair1.public)), "ECDSA")
        }
    }
}
