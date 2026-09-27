package com.tether.phone

import android.util.Log
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.net.InetSocketAddress
import java.net.SocketException
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

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

class TetherTlsTransport(
    private val securityEngine: ProductionSecurityEngine,
) : TetherTransport {

    companion object {
        private const val TAG = "TetherTlsTransport"
        private const val MAX_FRAME_SIZE = 1024 * 1024 // 1 MB limit

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
        Log.i(TAG, "Initiating secure TLS 1.3 connection to $safeHost:$port (gen=$generationId)...")

        val sslContext = createSslContext()
        val factory: SSLSocketFactory = sslContext.socketFactory

        val sslSock = factory.createSocket() as SSLSocket
        sslSock.useClientMode = true

        val sslParams = sslSock.sslParameters
        sslParams.endpointIdentificationAlgorithm = "HTTPS"
        sslSock.sslParameters = sslParams

        // Strictly enforce TLS 1.3 only
        sslSock.enabledProtocols = arrayOf("TLSv1.3")

        sslSock.connect(InetSocketAddress(host, port), timeoutMs)
        sslSock.soTimeout = 15000

        sslSock.startHandshake()
        val session = sslSock.session
        Log.i(TAG, "TLS 1.3 Handshake complete! Protocol=${session.protocol}, CipherSuite=${session.cipherSuite}")

        val peerCerts = session.peerCertificates
        if (peerCerts.isNotEmpty() && (peerCerts[0] is X509Certificate)) {
            val cert = peerCerts[0] as X509Certificate
            peerCertificate = cert
            peerFingerprint = securityEngine.computePublicKeyFingerprint(cert.publicKey.encoded)
            val safeFp = sanitizeLog(peerFingerprint)
            Log.i(TAG, "Peer TLS Identity SHA-256 Fingerprint: $safeFp")
        }

        this.sslSocket = sslSock
        this.dataInputStream = DataInputStream(sslSock.inputStream)
        this.dataOutputStream = DataOutputStream(sslSock.outputStream)
        this.connected = true
    }

    private fun createSslContext(): SSLContext {
        val sslContext = SSLContext.getInstance("TLSv1.3")
        sslContext.init(null, null, SecureRandom())
        return sslContext
    }

    @Synchronized
    override fun disconnect(reason: String) {
        if (!connected && (sslSocket == null)) return
        val safeReason = sanitizeLog(reason)
        Log.i(TAG, "Disconnecting TLS transport (gen=$generationId): $safeReason")
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
