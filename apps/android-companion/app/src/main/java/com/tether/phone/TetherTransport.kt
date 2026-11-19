package com.tether.phone

import android.annotation.SuppressLint
import android.content.Context
import android.util.Log
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.net.InetSocketAddress
import java.net.SocketException
import java.net.SocketTimeoutException
import java.nio.charset.StandardCharsets
import java.security.Principal
import java.security.PrivateKey
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509ExtendedKeyManager


interface TetherTransport {
    val generationId: Long
    fun connect(host: String, port: Int, timeoutMs: Int = 10000)
    fun disconnect(reason: String = "Normal disconnect")
    fun isConnected(): Boolean
    fun sendFrame(data: ByteArray)
    fun readFrame(maxSizeBytes: Int = 1024 * 1024): ByteArray?
    fun getPeerCertificate(): X509Certificate?
    fun getPeerIdentityFingerprint(): String?
}

@SuppressLint("CustomX509TrustManager")
class TetherTransportTrustManager(
    private val context: Context? = null,
    private val securityEngine: ProductionSecurityEngine,
    private val expectedPeerFingerprint: String? = null,
    private val expectedPeerPublicKey: ByteArray? = null,
) : javax.net.ssl.X509ExtendedTrustManager() {

    @Volatile
    private var lastVerifiedCert: X509Certificate? = null

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        throw CertificateException("Client certificates are not supported by this transport")
    }

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        verifyCertificate(chain)
    }

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: java.net.Socket?) {
        throw CertificateException("Client certificates are not supported by this transport")
    }

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: java.net.Socket?) {
        verifyCertificate(chain)
    }

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) {
        throw CertificateException("Client certificates are not supported by this transport")
    }

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) {
        verifyCertificate(chain)
    }

    fun checkServerTrusted(chain: Array<X509Certificate>, authType: String?, host: String?): List<X509Certificate> {
        verifyCertificate(chain)
        return chain.toList()
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> {
        val cert = lastVerifiedCert
        return if (cert != null) arrayOf(cert) else emptyArray()
    }

    fun verifyCertificate(chain: Array<out X509Certificate>?) {
        // 1. Reject null or empty certificate chains
        if (chain.isNullOrEmpty()) {
            throw CertificateException("Server certificate chain is null or empty")
        }

        // 2. Validate certificate validity periods for all certificates in chain
        for (cert in chain) {
            try {
                cert.checkValidity()
            } catch (e: Exception) {
                throw CertificateException("Certificate in server chain is invalid or expired: ${e.message}", e)
            }
        }

        val leaf = chain[0]

        // 3. Reject CA certificates being used as the peer's leaf identity certificate
        val basicConstraints = leaf.basicConstraints
        val keyUsage = leaf.keyUsage
        val isCa = (basicConstraints != -1) || (keyUsage != null && keyUsage.size > 5 && keyUsage[5])
        if (isCa) {
            throw CertificateException("Leaf certificate must be an end-entity identity certificate, not a CA certificate")
        }

        // 4. Validate that the public key uses the expected EC algorithm and has valid encoded key material
        val pubKey = leaf.publicKey
            ?: throw CertificateException("Leaf certificate contains null public key")
        val algorithm = pubKey.algorithm
        if (algorithm == null || (!algorithm.equals("EC", ignoreCase = true) && !algorithm.equals("ECDSA", ignoreCase = true))) {
            throw CertificateException("Leaf certificate public key algorithm is '$algorithm'; expected EC or ECDSA")
        }
        val leafKeyBytes = pubKey.encoded
        if (leafKeyBytes == null || leafKeyBytes.isEmpty()) {
            throw CertificateException("Leaf certificate public key encoded bytes are null or empty")
        }

        // Resolve pinned key state from explicit override or storage
        val pinnedBytes: ByteArray? = when {
            expectedPeerPublicKey != null && expectedPeerPublicKey.isNotEmpty() -> expectedPeerPublicKey
            context != null -> {
                when (val pinResult = securityEngine.getPinnedKeyResult(context)) {
                    is PinnedKeyResult.Present -> pinResult.keyBytes
                    is PinnedKeyResult.Corrupted -> {
                        // 11. Fail closed if stored pin cannot be retrieved due to storage/decryption error
                        throw CertificateException(
                            "Refusing connection: stored pinning material is corrupted or inaccessible",
                            pinResult.exception
                        )
                    }
                    is PinnedKeyResult.Unprovisioned -> null
                }
            }
            else -> null
        }

        // 5 & 6. When a pinned key exists, require exact constant-time comparison and reject mismatches
        if (pinnedBytes != null && pinnedBytes.isNotEmpty()) {
            if (!MessageDigest.isEqual(pinnedBytes, leafKeyBytes)) {
                throw CertificateException("Certificate pinning verification failed: public key mismatch")
            }
            lastVerifiedCert = leaf
            return
        }

        // 7, 8, 9, 10. First-contact Trust On First Use (TOFU) pairing path
        val expectedFp = expectedPeerFingerprint
        if (!expectedFp.isNullOrBlank()) {
            val leafFp = securityEngine.computePublicKeyFingerprint(leafKeyBytes)
            val expectedFpBytes = expectedFp.toByteArray(StandardCharsets.UTF_8)
            val leafFpBytes = leafFp.toByteArray(StandardCharsets.UTF_8)
            if (!MessageDigest.isEqual(expectedFpBytes, leafFpBytes)) {
                throw CertificateException("Certificate pinning verification failed: fingerprint mismatch with discovered identity")
            }
            Log.i(
                "TetherTransportTrustManager",
                "Accepting unpinned self-signed certificate at TLS layer during first-contact pairing. TLS acceptance does NOT authenticate peer; application-level pairing protocol must subsequently validate SPKI and complete interactive PIN + mutual proof before persisting trusted identity."
            )
            lastVerifiedCert = leaf
            return
        }

        throw CertificateException("Refusing connection: peer public key is not pinned and no expected discovered fingerprint was provided")
    }
}

class TetherTlsTransport(
    private val appContext: Context,
    private val securityEngine: ProductionSecurityEngine,
    private val expectedPeerFingerprint: String? = null,
    private val expectedPeerPublicKey: ByteArray? = null,
) : TetherTransport {

    companion object {
        private const val TAG = "TetherTlsTransport"
        private const val MAX_FRAME_SIZE = 1024 * 1024

        private fun sanitizeLog(input: String?): String {
            if (input == null) return "null"
            return input
                .replace("\r", "\\r")
                .replace("\n", "\\n")
                .replace("\t", "\\t")
                .filter { (it.code >= 0x20) && (it.code != 0x7F) }
                .take(256)
        }
    }

    override val generationId: Long = System.nanoTime()

    @Volatile
    private var rawSocket: java.net.Socket? = null
    private var sslSocket: SSLSocket? = null
    private var dataInputStream: DataInputStream? = null
    private var dataOutputStream: DataOutputStream? = null
    private var peerCertificate: X509Certificate? = null
    private var peerFingerprint: String? = null

    @Volatile
    private var connected = false

    override fun connect(host: String, port: Int, timeoutMs: Int) {
        if (connected) disconnect("Reconnecting")
        val safeHost = sanitizeLog(host)
        Log.i(TAG, "Initiating secure TLS 1.3 connection to $safeHost:$port (gen=$generationId)...")

        val sslContext = createSslContext()
        val factory: SSLSocketFactory = sslContext.socketFactory

        val raw = java.net.Socket()
        raw.tcpNoDelay = true
        this.rawSocket = raw
        try {
            raw.connect(InetSocketAddress(host, port), timeoutMs)
            raw.soTimeout = 120000

            val sslSock = factory.createSocket(raw, host, port, true) as SSLSocket
            sslSock.tcpNoDelay = true
            sslSock.useClientMode = true

            val sslParams = sslSock.sslParameters
            sslParams.endpointIdentificationAlgorithm = "HTTPS"
            sslSock.sslParameters = sslParams

            sslSock.enabledProtocols = arrayOf("TLSv1.3")

            sslSock.startHandshake()
            val session = sslSock.session
            Log.i(TAG, "TLS 1.3 Handshake complete! Protocol=${session.protocol}, CipherSuite=${session.cipherSuite}")

            val peerCerts = session.peerCertificates
            if (peerCerts.isEmpty() || (peerCerts[0] !is X509Certificate)) {
                sslSock.close()
                throw SSLException("No valid X.509 peer certificate presented during TLS handshake")
            }

            val cert = peerCerts[0] as X509Certificate

            peerCertificate = cert
            peerFingerprint = securityEngine.computePublicKeyFingerprint(cert.publicKey.encoded)
            val safeFp = sanitizeLog(peerFingerprint)
            Log.i(TAG, "Peer TLS Identity SHA-256 Fingerprint: $safeFp")

            this.sslSocket = sslSock
            this.dataInputStream = DataInputStream(sslSock.inputStream)
            this.dataOutputStream = DataOutputStream(sslSock.outputStream)
            this.connected = true
        } catch (e: Exception) {
            disconnect("Connect failed: ${e.message}")
            throw e
        }
    }

    private fun createSslContext(): SSLContext {
        val pinningTrustManager = TetherTransportTrustManager(
            context = appContext,
            securityEngine = securityEngine,
            expectedPeerFingerprint = expectedPeerFingerprint,
            expectedPeerPublicKey = expectedPeerPublicKey,
        )

        val customKeyManager = object : X509ExtendedKeyManager() {
            override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?): Array<String> = arrayOf("TetherIdentity")
            override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: java.net.Socket?): String = "TetherIdentity"
            override fun chooseEngineClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, engine: SSLEngine?): String = "TetherIdentity"
            override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?): Array<String> = emptyArray()
            override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: java.net.Socket?): String? = null
            override fun chooseEngineServerAlias(keyType: String?, issuers: Array<out Principal>?, engine: SSLEngine?): String? = null
            override fun getCertificateChain(alias: String?): Array<X509Certificate>? {
                return try {
                    arrayOf(securityEngine.getIdentityCertificate())
                } catch (e: Exception) {
                    Log.w(TAG, "Failed retrieving identity certificate for TLS client auth: ${e.message}")
                    null
                }
            }
            override fun getPrivateKey(alias: String?): PrivateKey? {
                return try {
                    securityEngine.getIdentityPrivateKey()
                } catch (e: Exception) {
                    Log.w(TAG, "Failed retrieving identity private key for TLS client auth: ${e.message}")
                    null
                }
            }
        }

        val sslContext = SSLContext.getInstance("TLSv1.3")
        sslContext.init(arrayOf(customKeyManager), arrayOf<TrustManager>(pinningTrustManager), SecureRandom())
        return sslContext
    }

    @Synchronized
    override fun disconnect(reason: String) {
        if (!connected && (sslSocket == null) && (rawSocket == null)) return
        val safeReason = sanitizeLog(reason)
        Log.i(TAG, "Disconnecting TLS transport (gen=$generationId): $safeReason")
        connected = false
        try { dataInputStream?.close() } catch (_: Exception) {}
        try { dataOutputStream?.close() } catch (_: Exception) {}
        try { sslSocket?.close() } catch (_: Exception) {}
        try { rawSocket?.close() } catch (_: Exception) {}
        dataInputStream = null
        dataOutputStream = null
        sslSocket = null
        rawSocket = null
        peerCertificate = null
        peerFingerprint = null
    }

    override fun isConnected(): Boolean = connected && (sslSocket?.isConnected == true)

    override fun sendFrame(data: ByteArray) {
        if (!isConnected()) throw IllegalStateException("Transport disconnected")
        if (data.size > MAX_FRAME_SIZE) throw IllegalArgumentException("Frame size ${data.size} exceeds maximum limit of $MAX_FRAME_SIZE bytes")
        val dos = dataOutputStream ?: throw IllegalStateException("OutputStream null")
        synchronized(dos) {
            dos.writeInt(data.size)
            dos.write(data)
            dos.flush()
        }
    }

    override fun readFrame(maxSizeBytes: Int): ByteArray? {
        if (!isConnected()) return null
        val dis = dataInputStream ?: return null

        val length = try {
            dis.readInt()
        } catch (_: EOFException) {
            Log.i(TAG, "EOF reached on TLS socket (gen=$generationId)")
            disconnect("Socket EOF")
            return null
        } catch (_: SocketTimeoutException) {
            return null
        } catch (e: SocketException) {
            Log.w(TAG, "SocketException reading frame: ${e.message}")
            disconnect("SocketException: ${e.message}")
            return null
        } catch (e: SSLException) {
            Log.w(TAG, "SSLException reading frame: ${e.message}")
            disconnect("SSLException: ${e.message}")
            return null
        } catch (e: IOException) {
            Log.w(TAG, "IOException reading frame: ${e.message}")
            disconnect("IOException: ${e.message}")
            return null
        }

        if ((length < 1) || (length > maxSizeBytes)) {
            Log.e(TAG, "Invalid frame length received: $length bytes (limit: $maxSizeBytes)")
            disconnect("Oversized or invalid frame length: $length")
            return null
        }

        val buffer = ByteArray(length)
        try {
            dis.readFully(buffer)
        } catch (e: Exception) {
            Log.w(TAG, "Failed reading frame body ($length bytes): ${e.message}")
            disconnect("Frame readFully error: ${e.message}")
            return null
        }

        return buffer
    }

    override fun getPeerCertificate(): X509Certificate? = peerCertificate

    override fun getPeerIdentityFingerprint(): String? = peerFingerprint
}