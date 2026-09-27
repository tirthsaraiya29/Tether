package com.tether.phone

import android.util.Log
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

interface TetherTransport {
    fun connect(host: String, port: Int, timeoutMs: Int = 10000)
    fun disconnect(reason: String = "Normal disconnect")
    fun isConnected(): Boolean
    fun sendFrame(data: ByteArray)
    fun readFrame(maxSizeBytes: Int = 1024 * 1024): ByteArray?
    fun getPeerCertificate(): X509Certificate?
    fun getPeerIdentityFingerprint(): String?
    fun attachSessionCipher(cipher: SessionCipher?)
    fun getSessionCipher(): SessionCipher?
}

class TetherTlsTransport(
    private val securityEngine: ProductionSecurityEngine
) : TetherTransport {

    companion object {
        private const val TAG = "TetherTlsTransport"
        private const val MAX_FRAME_SIZE = 1024 * 1024 // 1 MB limit
    }

    private var sslSocket: SSLSocket? = null
    private var dataInputStream: DataInputStream? = null
    private var dataOutputStream: DataOutputStream? = null
    private var peerCertificate: X509Certificate? = null
    private var peerFingerprint: String? = null

    @Volatile
    private var sessionCipher: SessionCipher? = null

    @Volatile
    private var connected = false

    override fun attachSessionCipher(cipher: SessionCipher?) {
        this.sessionCipher = cipher
        Log.i(TAG, "Attached SessionCipher to TLS transport (active=${cipher != null})")
    }

    override fun getSessionCipher(): SessionCipher? = sessionCipher

    override fun connect(host: String, port: Int, timeoutMs: Int) {
        if (connected) disconnect("Reconnecting")
        Log.i(TAG, "Initiating secure TLS 1.3 connection to $host:$port...")

        val sslContext = createSslContext()
        val factory: SSLSocketFactory = sslContext.socketFactory

        val rawSocket = Socket()
        rawSocket.connect(InetSocketAddress(host, port), timeoutMs)
        rawSocket.soTimeout = 15000

        val sslSock = factory.createSocket(rawSocket, host, port, true) as SSLSocket
        sslSock.useClientMode = true

        // Strictly enforce TLS 1.3 only to prevent version downgrade attacks
        sslSock.enabledProtocols = arrayOf("TLSv1.3")

        sslSock.startHandshake()
        val session = sslSock.session
        Log.i(TAG, "TLS 1.3 Handshake complete! Protocol=${session.protocol}, CipherSuite=${session.cipherSuite}")

        val peerCerts = session.peerCertificates
        if (peerCerts.isNotEmpty() && peerCerts[0] is X509Certificate) {
            val cert = peerCerts[0] as X509Certificate
            peerCertificate = cert
            peerFingerprint = securityEngine.computePublicKeyFingerprint(cert.publicKey.encoded)
            Log.i(TAG, "Peer TLS Identity SHA-256 Fingerprint: $peerFingerprint")
        }

        this.sslSocket = sslSock
        this.dataInputStream = DataInputStream(sslSock.inputStream)
        this.dataOutputStream = DataOutputStream(sslSock.outputStream)
        this.connected = true
    }

    private fun createSslContext(): SSLContext {
        val sslContext = SSLContext.getInstance("TLSv1.3")

        val trustManager = object : X509TrustManager {
            @Suppress("TrustAllX509TrustManager")
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            @Suppress("TrustAllX509TrustManager")
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                if (chain.isNullOrEmpty()) {
                    throw CertificateException("Empty TLS certificate chain received from server")
                }
            }
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }

        sslContext.init(null, arrayOf<TrustManager>(trustManager), SecureRandom())
        return sslContext
    }

    override fun disconnect(reason: String) {
        Log.i(TAG, "Disconnecting TLS transport: $reason")
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

    override fun sendFrame(data: ByteArray) {
        if (!isConnected()) throw IllegalStateException("Transport disconnected")

        val payload = sessionCipher?.encrypt(data) ?: data
        if (payload.size > MAX_FRAME_SIZE) throw IllegalArgumentException("Frame size ${payload.size} exceeds maximum limit of $MAX_FRAME_SIZE bytes")

        val dos = dataOutputStream ?: throw IllegalStateException("OutputStream null")
        synchronized(dos) {
            dos.writeInt(payload.size)
            dos.write(payload)
            dos.flush()
        }
    }

    override fun readFrame(maxSizeBytes: Int): ByteArray? {
        if (!isConnected()) return null
        val dis = dataInputStream ?: return null

        val length = try { dis.readInt() } catch (_: Exception) { return null }
        if (length <= 0 || length > maxSizeBytes) {
            Log.e(TAG, "Invalid frame length received: $length bytes (limit: $maxSizeBytes)")
            disconnect("Oversized or invalid frame length: $length")
            return null
        }

        val buffer = ByteArray(length)
        dis.readFully(buffer)

        val cipher = sessionCipher
        return if (cipher != null) {
            cipher.decrypt(buffer)
        } else {
            buffer
        }
    }

    override fun getPeerCertificate(): X509Certificate? = peerCertificate

    override fun getPeerIdentityFingerprint(): String? = peerFingerprint
}
