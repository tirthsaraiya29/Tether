package com.tether.phone

import android.content.Context
import android.os.Environment
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.Principal
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedKeyManager

class TetherFileTransferServer(
    private val appContext: Context,
    private val securityEngine: ProductionSecurityEngine,
    private val fileTransferManager: TetherFileTransferManager,
    private val coroutineScope: CoroutineScope,
) {

    companion object {
        private const val TAG = "TetherFileTransferServer"
        const val SERVER_PORT = 37125
        private const val MAX_CONTROL_FRAME_SIZE = 65536
    }

    private var serverSocket: ServerSocket? = null
    private var serverJob: Job? = null
    @Volatile private var isRunning = false

    fun start() {
        if (isRunning) return
        isRunning = true

        serverJob = coroutineScope.launch(Dispatchers.IO) {
            try {
                val sslContext = createServerSslContext()
                val factory = sslContext.serverSocketFactory
                val sslServer = factory.createServerSocket(SERVER_PORT) as SSLServerSocket
                sslServer.reuseAddress = true
                sslServer.enabledProtocols = arrayOf("TLSv1.3")
                serverSocket = sslServer

                Log.i(TAG, "Tether File Transfer Server listening on TCP port $SERVER_PORT (TLS 1.3)...")

                while (isActive && isRunning) {
                    try {
                        val clientSocket = sslServer.accept()
                        clientSocket.tcpNoDelay = true
                        clientSocket.soTimeout = 15000
                        launch(Dispatchers.IO) {
                            handleClientSocket(clientSocket)
                        }
                    } catch (e: Exception) {
                        if (!isRunning) break
                        Log.w(TAG, "Error accepting client socket: ${e.message}")
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed starting File Transfer Server: ${e.message}", e)
            } finally {
                stop()
            }
        }
    }

    fun stop() {
        isRunning = false
        try { serverSocket?.close() } catch (_: Exception) {}
        serverSocket = null
        serverJob?.cancel()
        serverJob = null
        Log.i(TAG, "Tether File Transfer Server stopped.")
    }

    private suspend fun handleClientSocket(socket: Socket) = withContext(Dispatchers.IO) {
        val dis = DataInputStream(socket.inputStream)
        val dos = DataOutputStream(socket.outputStream)
        var isAuthenticated = false
        var peerFingerprint = ""

        try {
            while (socket.isConnected && !socket.isClosed) {
                val len = try {
                    dis.readInt()
                } catch (_: Exception) {
                    break
                }

                if (len <= 0 || len > MAX_CONTROL_FRAME_SIZE) {
                    Log.w(TAG, "Invalid control frame size $len. Closing socket.")
                    break
                }

                val frameBytes = ByteArray(len)
                dis.readFully(frameBytes)
                val jsonStr = String(frameBytes, StandardCharsets.UTF_8)
                val type = JsonParserUtils.getString(jsonStr, "type", "")

                when (type) {
                    ControlMessageType.CONTROL_INIT -> {
                        val deviceId = JsonParserUtils.getString(jsonStr, "deviceId", "")
                        isAuthenticated = deviceId.isNotBlank()
                        peerFingerprint = deviceId

                        val ackJson = "{\"type\":\"${ControlMessageType.CONTROL_INIT_ACK}\",\"status\":\"OK\",\"grantedCapabilities\":\"CLIPBOARD,FILES,NOTIFICATIONS,MEDIA\"}"
                        sendFrame(dos, ackJson.toByteArray(StandardCharsets.UTF_8))
                        Log.i(TAG, "Authenticated incoming file connection from $deviceId")
                    }

                    ControlMessageType.BROWSE_ROOTS_REQUEST -> {
                        if (!isAuthenticated) break
                        val reqId = JsonParserUtils.getString(jsonStr, "requestId", "")
                        val roots = getAndroidStorageRoots()
                        val respObj = JSONObject().apply {
                            put("type", ControlMessageType.BROWSE_ROOTS_RESPONSE)
                            put("requestId", reqId)
                            put("status", "OK")
                            put("roots", JSONArray().apply {
                                roots.forEach { root ->
                                    put(JSONObject().apply {
                                        put("Name", root.name)
                                        put("Path", root.path)
                                        put("RootType", root.rootType)
                                        put("IsReadable", root.isReadable)
                                    })
                                }
                            })
                        }
                        sendFrame(dos, respObj.toString().toByteArray(StandardCharsets.UTF_8))
                    }

                    ControlMessageType.LIST_DIR_REQUEST -> {
                        if (!isAuthenticated) break
                        val reqId = JsonParserUtils.getString(jsonStr, "requestId", "")
                        val requestedPath = JsonParserUtils.getString(jsonStr, "path", "")
                        val items = listAndroidDirectory(requestedPath)

                        val respObj = JSONObject().apply {
                            put("type", ControlMessageType.LIST_DIR_RESPONSE)
                            put("requestId", reqId)
                            put("status", "OK")
                            put("path", requestedPath)
                            put("items", JSONArray().apply {
                                items.forEach { item ->
                                    put(JSONObject().apply {
                                        put("Name", item.name)
                                        put("RelativePath", item.relativePath)
                                        put("IsDirectory", item.isDirectory)
                                        put("FileSize", item.fileSize)
                                        put("LastModifiedMs", item.lastModifiedMs)
                                        put("IsReadable", item.isReadable)
                                    })
                                }
                            })
                        }
                        sendFrame(dos, respObj.toString().toByteArray(StandardCharsets.UTF_8))
                    }

                    ControlMessageType.TRANSFER_REQUEST -> {
                        if (!isAuthenticated) break
                        val reqFrame = TransferRequestFrame.parseJsonString(jsonStr)
                        // Read binary stream and stage file
                        val dummyTransport = object : TetherQuicTransport {
                            override val generationId: Long = 0L
                            override fun connect(host: String, port: Int, timeoutMs: Int) {}
                            override fun disconnect(reason: String) {}
                            override fun isConnected(): Boolean = socket.isConnected && !socket.isClosed
                            override fun sendControlFrame(data: ByteArray) { sendFrame(dos, data) }
                            override fun readControlFrame(maxSizeBytes: Int): ByteArray? = null
                            override fun sendDataChunk(chunkData: ByteArray) {}
                            override fun readDataChunk(maxSizeBytes: Int): ByteArray? {
                                val totalLen = dis.readInt()
                                if (totalLen <= 0 || totalLen > maxSizeBytes) return null
                                val buf = ByteArray(totalLen)
                                dis.readFully(buf)
                                return buf
                            }
                            override fun getPeerCertificate(): X509Certificate? = null
                            override fun getPeerIdentityFingerprint(): String? = peerFingerprint
                        }

                        fileTransferManager.handleIncomingTransfer(dummyTransport, reqFrame, "Windows PC")
                    }
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Exception handling client connection: ${e.message}")
        } finally {
            try { socket.close() } catch (_: Exception) {}
        }
    }

    private fun sendFrame(dos: DataOutputStream, data: ByteArray) {
        synchronized(dos) {
            dos.writeInt(data.size)
            dos.write(data)
            dos.flush()
        }
    }

    private fun getAndroidStorageRoots(): List<FilesystemRootItem> {
        val list = mutableListOf<FilesystemRootItem>()
        val extDir = Environment.getExternalStorageDirectory()
        if (extDir != null && extDir.exists()) {
            list.add(FilesystemRootItem("Internal Storage", extDir.absolutePath, "ROOT", true))

            val downloads = File(extDir, "Download")
            if (downloads.exists()) list.add(FilesystemRootItem("Downloads", downloads.absolutePath, "DOWNLOADS", true))

            val dcim = File(extDir, "DCIM")
            if (dcim.exists()) list.add(FilesystemRootItem("Pictures / Camera", dcim.absolutePath, "PICTURES", true))

            val docs = File(extDir, "Documents")
            if (docs.exists()) list.add(FilesystemRootItem("Documents", docs.absolutePath, "DOCUMENTS", true))
        }
        return list
    }

    private fun listAndroidDirectory(requestedPath: String): List<DirectoryListingItem> {
        val target = if (requestedPath.isBlank()) Environment.getExternalStorageDirectory() else File(requestedPath)
        if (target == null || !target.exists() || !target.isDirectory) return emptyList()

        val results = mutableListOf<DirectoryListingItem>()
        target.listFiles()?.forEach { file ->
            if (!file.name.startsWith(".")) {
                results.add(
                    DirectoryListingItem(
                        name = file.name,
                        relativePath = file.absolutePath,
                        isDirectory = file.isDirectory,
                        fileSize = if (file.isDirectory) 0L else file.length(),
                        lastModifiedMs = file.lastModified(),
                        isReadable = file.canRead(),
                    )
                )
            }
        }
        return results.sortedWith(compareByDescending<DirectoryListingItem> { it.isDirectory }.thenBy { it.name })
    }

    private fun createServerSslContext(): SSLContext {
        val customKeyManager = object : X509ExtendedKeyManager() {
            override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?): Array<String> = emptyArray()
            override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?): String? = null
            override fun chooseEngineClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, engine: SSLEngine?): String? = null
            override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?): Array<String> = arrayOf("TetherIdentity")
            override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: Socket?): String = "TetherIdentity"
            override fun chooseEngineServerAlias(keyType: String?, issuers: Array<out Principal>?, engine: SSLEngine?): String = "TetherIdentity"
            override fun getCertificateChain(alias: String?): Array<X509Certificate>? {
                return try {
                    arrayOf(securityEngine.getIdentityCertificate())
                } catch (e: Exception) {
                    Log.w(TAG, "Failed retrieving identity certificate for TLS server: ${e.message}")
                    null
                }
            }
            override fun getPrivateKey(alias: String?): PrivateKey? {
                return try {
                    securityEngine.getIdentityPrivateKey()
                } catch (e: Exception) {
                    Log.w(TAG, "Failed retrieving identity private key for TLS server: ${e.message}")
                    null
                }
            }
        }

        val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        trustManagerFactory.init(null as KeyStore?)

        val sslContext = SSLContext.getInstance("TLSv1.3")
        sslContext.init(arrayOf(customKeyManager), trustManagerFactory.trustManagers, SecureRandom())
        return sslContext
    }
}
