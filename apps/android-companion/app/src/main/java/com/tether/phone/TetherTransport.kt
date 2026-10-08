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
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager


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
    private val appContext: Context,
    private val securityEngine: ProductionSecurityEngine,
) : TetherTransport {

    companion object {
        private const val TAG = "TetherTlsTransport"
        private const val MAX_FRAME_SIZE = 1024 * 1024

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

        val rawSocket = java.net.Socket()
        rawSocket.connect(InetSocketAddress(host, port), timeoutMs)
        rawSocket.soTimeout = 15000

        val sslSock = factory.createSocket(rawSocket, host, port, true) as SSLSocket
        sslSock.useClientMode = true

        val sslParams = sslSock.getSSLParameters()
        sslParams.setEndpointIdentificationAlgorithm("HTTPS")
        sslSock.setSSLParameters(sslParams)

        sslSock.enabledProtocols = arrayOf("TLSv1.3")

        sslSock.startHandshake()
        val session = sslSock.session
        Log.i(TAG, "TLS 1.3 Handshake complete! Protocol=${session.protocol}, CipherSuite=${session.cipherSuite}")

        val peerCerts = session.peerCertificates
        if (peerCerts.isEmpty() || peerCerts[0] !is X509Certificate) {
            sslSock.close()
            throw SSLException("No valid X.509 peer certificate presented during TLS handshake")
        }

        val cert = peerCerts[0] as X509Certificate
        cert.checkValidity()

        val pinnedBytes = securityEngine.getPinnedKeyDecrypted(appContext) as ByteArray?
        if (pinnedBytes != null && pinnedBytes.isNotEmpty()) {
            val md = MessageDigest.getInstance("SHA-256")
            val presentedHash = md.digest(cert.publicKey.encoded)
            if (!MessageDigest.isEqual(pinnedBytes, presentedHash)) {
                sslSock.close()
                throw SSLException("Certificate pinning verification failed: public key fingerprint mismatch")
            }
        }

        peerCertificate = cert
        peerFingerprint = securityEngine.computePublicKeyFingerprint(cert.publicKey.encoded)
        val safeFp = sanitizeLog(peerFingerprint)
        Log.i(TAG, "Peer TLS Identity SHA-256 Fingerprint: $safeFp")

        this.sslSocket = sslSock
        this.dataInputStream = DataInputStream(sslSock.inputStream)
        this.dataOutputStream = DataOutputStream(sslSock.outputStream)
        this.connected = true
    }

    @SuppressLint("CustomX509TrustManager")
    private fun createSslContext(): SSLContext {
        val pinnedBytes = securityEngine.getPinnedKeyDecrypted(appContext) as ByteArray?

        // Suppress CodeQL false positive: Implements Trust-On-First-Use (TOFU) pinning for peer-to-peer self-signed TLS connections.
        // codeql[java/unsafe-cert-trust]
        // codeql[java/insecure-trustmanager]
        val pinningTrustManager = object : javax.net.ssl.X509ExtendedTrustManager() {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                throw CertificateException("Client certificates are not supported by this transport")
            }

            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                checkPinning(chain)
            }

            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: java.net.Socket?) {
                throw CertificateException("Client certificates are not supported by this transport")
            }

            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: java.net.Socket?) {
                checkPinning(chain)
            }

            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: javax.net.ssl.SSLEngine?) {
                throw CertificateException("Client certificates are not supported by this transport")
            }

            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: javax.net.ssl.SSLEngine?) {
                checkPinning(chain)
            }

            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()

            private fun checkPinning(chain: Array<out X509Certificate>?) {
                if (chain.isNullOrEmpty()) {
                    throw CertificateException("Server certificate chain is null or empty")
                }
                val leaf = chain[0]
                leaf.checkValidity() // Validate certificate validity dates

                // If a pinned key is saved (paired state), strictly enforce public key fingerprint matching.
                // If pinnedBytes is null (unpaired / TOFU mode), allow TLS handshake to complete
                // so executeHandshake() can verify the PIN and show the PairingConfirmationActivity popup.
                if (pinnedBytes != null && pinnedBytes.isNotEmpty()) {
                    val md = MessageDigest.getInstance("SHA-256")
                    val presentedHash = md.digest(leaf.publicKey.encoded)
                    if (!MessageDigest.isEqual(pinnedBytes, presentedHash)) {
                        throw CertificateException("Certificate pinning verification failed: public key fingerprint mismatch")
                    }
                }
            }
        }

        val sslContext = SSLContext.getInstance("TLSv1.3")
        sslContext.init(null, arrayOf<TrustManager>(pinningTrustManager), SecureRandom())
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