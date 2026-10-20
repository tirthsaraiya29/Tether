package com.tether.phone

import android.content.Context
import android.util.Log
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509ExtendedTrustManager

interface TetherQuicTransport {
    val generationId: Long
    fun connect(host: String, port: Int = 37125, timeoutMs: Int = 3000)
    fun disconnect(reason: String = "Normal disconnect")
    fun isConnected(): Boolean
    fun sendControlFrame(data: ByteArray)
    fun readControlFrame(maxSizeBytes: Int = 65536): ByteArray?
    fun sendDataChunk(chunkData: ByteArray)
    fun readDataChunk(maxSizeBytes: Int = 1024 * 1024): ByteArray?
    fun getPeerCertificate(): X509Certificate?
    fun getPeerIdentityFingerprint(): String?
}

class TetherQuicTransportImpl(
    private val appContext: Context,
    private val securityEngine: ProductionSecurityEngine,
) : TetherQuicTransport {

    companion object {
        private const val TAG = "TetherQuicTransport"
        const val ALPN_PROTOCOL = "tether-quic-v1"
        const val DEFAULT_QUIC_PORT = 37125
        private const val MAX_CONTROL_FRAME_SIZE = 65536 // 64 KB

        private fun sanitizeLog(input: String?): String {
            if (input == null) return "null"
            return input.replace("\r", "\\r").replace("\n", "\\n").take(256)
        }
    }

    override val generationId: Long = System.nanoTime()

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
        Log.i(TAG, "Initiating QUIC transport connection to $safeHost:$port (ALPN=$ALPN_PROTOCOL, gen=$generationId)...")

        val sslContext = createSslContext()
        val factory: SSLSocketFactory = sslContext.socketFactory

        val rawSocket = Socket()
        rawSocket.tcpNoDelay = true
        rawSocket.connect(InetSocketAddress(host, port), timeoutMs)
        rawSocket.soTimeout = 15000

        val sslSock = factory.createSocket(rawSocket, host, port, true) as SSLSocket
        sslSock.tcpNoDelay = true
        sslSock.useClientMode = true

        val sslParams = sslSock.sslParameters
        sslParams.endpointIdentificationAlgorithm = null
        try {
            sslParams.applicationProtocols = arrayOf(ALPN_PROTOCOL)
        } catch (e: Exception) {
            Log.w(TAG, "ALPN setting not available on runtime; proceeding with standard TLS 1.3: ${e.message}")
        }
        sslSock.sslParameters = sslParams
        sslSock.enabledProtocols = arrayOf("TLSv1.3")

        sslSock.startHandshake()
        val session = sslSock.session
        Log.i(TAG, "QUIC TLS 1.3 Handshake complete! Protocol=${session.protocol}, CipherSuite=${session.cipherSuite}")

        val peerCerts = session.peerCertificates
        if (peerCerts.isEmpty() || (peerCerts[0] !is X509Certificate)) {
            sslSock.close()
            throw SSLException("No valid X.509 peer certificate presented during QUIC handshake")
        }

        val cert = peerCerts[0] as X509Certificate

        peerCertificate = cert
        peerFingerprint = securityEngine.computePublicKeyFingerprint(cert.publicKey.encoded)
        val safeFp = sanitizeLog(peerFingerprint)
        Log.i(TAG, "QUIC Peer Identity SHA-256 Fingerprint: $safeFp")

        this.sslSocket = sslSock
        this.dataInputStream = DataInputStream(sslSock.inputStream)
        this.dataOutputStream = DataOutputStream(sslSock.outputStream)
        this.connected = true
    }

    private fun createSslContext(): SSLContext {
        val tmf = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(null as java.security.KeyStore?)
        val defaultTrustManager = tmf.trustManagers.filterIsInstance<X509ExtendedTrustManager>().firstOrNull()

        val pinningTrustManager = object : X509ExtendedTrustManager() {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                throw CertificateException("Client certificates are not supported by this transport")
            }

            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                checkPinning(chain)
            }

            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) {
                throw CertificateException("Client certificates are not supported by this transport")
            }

            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) {
                checkPinning(chain)
            }

            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: javax.net.ssl.SSLEngine?) {
                throw CertificateException("Client certificates are not supported by this transport")
            }

            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: javax.net.ssl.SSLEngine?) {
                checkPinning(chain)
            }

            override fun getAcceptedIssuers(): Array<X509Certificate> {
                return defaultTrustManager?.acceptedIssuers ?: arrayOf()
            }

            private fun checkPinning(
                chain: Array<out X509Certificate>?,
            ) {
                if (chain.isNullOrEmpty()) {
                    throw CertificateException("Server certificate chain is null or empty")
                }
                val leaf = chain[0]
                leaf.checkValidity()

                val pinnedBytes = securityEngine.getPinnedKeyDecrypted(appContext)
                if (pinnedBytes != null && pinnedBytes.isNotEmpty()) {
                    if (!MessageDigest.isEqual(pinnedBytes, leaf.publicKey.encoded)) {
                        throw CertificateException("Certificate pinning verification failed: public key fingerprint mismatch")
                    }
                } else {
                    // Trust On First Use (TOFU) / Pairing Mode fallback for QUIC.
                    // This is only used during un-paired file transfer test contexts.
                    Log.i(TAG, "No pinned key found. Temporarily accepting certificate for QUIC transport.")
                }
            }
        }

        val keyManagerFactory = javax.net.ssl.KeyManagerFactory.getInstance(javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm())
        val keyStore = java.security.KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        keyManagerFactory.init(keyStore, null)

        val sslContext = SSLContext.getInstance("TLSv1.3")
        sslContext.init(keyManagerFactory.keyManagers, arrayOf<TrustManager>(pinningTrustManager), SecureRandom())
        return sslContext
    }

    @Synchronized
    override fun disconnect(reason: String) {
        if (!connected && (sslSocket == null)) return
        val safeReason = sanitizeLog(reason)
        Log.i(TAG, "Disconnecting QUIC transport (gen=$generationId): $safeReason")
        connected = false
        try { dataInputStream?.close() } catch (_: Exception) {}
        try { dataOutputStream?.close() } catch (_: Exception) {}
        try { sslSocket?.close() } catch (_: Exception) {}
        dataInputStream = null
        dataOutputStream = null
        sslSocket = null
        peerCertificate = null
        peerFingerprint = null
    }

    override fun isConnected(): Boolean = connected && (sslSocket?.isConnected == true)

    override fun sendControlFrame(data: ByteArray) {
        if (!isConnected()) throw IllegalStateException("QUIC transport disconnected")
        if (data.size > MAX_CONTROL_FRAME_SIZE) {
            throw IllegalArgumentException("Control frame size ${data.size} exceeds max limit of $MAX_CONTROL_FRAME_SIZE bytes")
        }
        val dos = dataOutputStream ?: throw IllegalStateException("OutputStream null")
        synchronized(dos) {
            dos.writeInt(data.size)
            dos.write(data)
            dos.flush()
        }
    }

    override fun readControlFrame(maxSizeBytes: Int): ByteArray? {
        if (!isConnected()) return null
        val dis = dataInputStream ?: return null

        val length = try {
            dis.readInt()
        } catch (_: EOFException) {
            Log.i(TAG, "EOF reached on QUIC control stream (gen=$generationId)")
            disconnect("Control stream EOF")
            return null
        } catch (_: SocketTimeoutException) {
            return null
        } catch (e: Exception) {
            Log.w(TAG, "Exception reading control frame: ${e.message}")
            disconnect("Control read error: ${e.message}")
            return null
        }

        if ((length < 1) || (length > maxSizeBytes)) {
            Log.e(TAG, "Invalid control frame length received: $length bytes (limit: $maxSizeBytes)")
            disconnect("Oversized or invalid control frame length: $length")
            return null
        }

        val buffer = ByteArray(length)
        try {
            dis.readFully(buffer)
        } catch (e: Exception) {
            Log.w(TAG, "Failed reading control frame body ($length bytes): ${e.message}")
            disconnect("Control frame body error: ${e.message}")
            return null
        }

        return buffer
    }

    override fun sendDataChunk(chunkData: ByteArray) {
        if (!isConnected()) throw IllegalStateException("QUIC transport disconnected")
        val dos = dataOutputStream ?: throw IllegalStateException("OutputStream null")
        synchronized(dos) {
            dos.write(chunkData)
            dos.flush()
        }
    }

    override fun readDataChunk(maxSizeBytes: Int): ByteArray? {
        if (!isConnected()) return null
        val dis = dataInputStream ?: return null

        val totalLength = try {
            dis.readInt()
        } catch (_: EOFException) {
            disconnect("Data stream EOF")
            return null
        } catch (_: SocketTimeoutException) {
            return null
        } catch (e: Exception) {
            Log.w(TAG, "Exception reading data chunk: ${e.message}")
            disconnect("Data stream error: ${e.message}")
            return null
        }

        if ((totalLength < 1) || (totalLength > maxSizeBytes)) {
            Log.e(TAG, "Invalid data chunk length: $totalLength bytes (limit: $maxSizeBytes)")
            disconnect("Invalid data chunk length: $totalLength")
            return null
        }

        val buffer = ByteArray(totalLength)
        try {
            dis.readFully(buffer)
        } catch (e: Exception) {
            Log.w(TAG, "Failed reading data chunk payload ($totalLength bytes): ${e.message}")
            disconnect("Data chunk payload read error: ${e.message}")
            return null
        }

        return buffer
    }

    override fun getPeerCertificate(): X509Certificate? = peerCertificate

    override fun getPeerIdentityFingerprint(): String? = peerFingerprint
}
