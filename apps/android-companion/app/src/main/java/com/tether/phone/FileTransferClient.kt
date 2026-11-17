package com.tether.phone

import android.content.Context
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okio.BufferedSink
import org.json.JSONArray
import org.json.JSONObject
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.net.Socket
import java.security.MessageDigest
import java.security.Principal
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.TrustManager
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509ExtendedTrustManager

data class FileNode(
    val name: String,
    val isDirectory: Boolean,
    val size: Long,
    val modifiedMs: Long,
    val path: String
)

class TetherPinnedTrustManager(
    private val context: Context?,
    private val overridePinnedKey: ByteArray? = null
) : X509ExtendedTrustManager() {

    @Volatile
    private var lastVerifiedCert: X509Certificate? = null

    init {
        try {
            val service = TetherLanService.instance
            val peerCert = service?.getActivePeerCertificate()
            if (peerCert != null) {
                lastVerifiedCert = peerCert
            }
        } catch (_: Exception) { }
    }

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        throw CertificateException("Client certificates are not supported by this trust manager")
    }

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        verifyPinning(chain)
    }

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) {
        throw CertificateException("Client certificates are not supported by this trust manager")
    }

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) {
        verifyPinning(chain)
    }

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) {
        throw CertificateException("Client certificates are not supported by this trust manager")
    }

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) {
        verifyPinning(chain)
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> {
        val cert = lastVerifiedCert
        return if (cert != null) arrayOf(cert) else arrayOf()
    }

    /**
     * Platform-extension method invoked via reflection by Android's [android.net.http.X509TrustManagerExtensions]
     * during OkHttp CertificateChainCleaner execution.
     */
    fun checkServerTrusted(chain: Array<X509Certificate>, authType: String?, host: String?): List<X509Certificate> {
        verifyPinning(chain)
        return chain.toList()
    }

    fun verifyPinning(chain: Array<out X509Certificate>?) {
        if (chain.isNullOrEmpty()) {
            throw CertificateException("Server certificate chain is null or empty")
        }
        for (cert in chain) {
            try {
                cert.checkValidity()
            } catch (e: Exception) {
                throw CertificateException("Certificate in chain is invalid or expired: ${e.message}", e)
            }
        }

        val leaf = chain[0]
        val basicConstraints = leaf.basicConstraints
        val keyUsage = leaf.keyUsage
        val isCa = (basicConstraints != -1) || (keyUsage != null && keyUsage.size > 5 && keyUsage[5])
        if (isCa) {
            throw CertificateException("Leaf certificate cannot be a CA certificate; end-entity identity certificate expected")
        }

        val pubKey = leaf.publicKey
            ?: throw CertificateException("Leaf certificate public key is null")
        val algorithm = pubKey.algorithm
        if (algorithm == null || (!algorithm.equals("EC", ignoreCase = true) && !algorithm.equals("ECDSA", ignoreCase = true))) {
            throw CertificateException("Leaf certificate public key algorithm is '$algorithm'; expected EC or ECDSA")
        }
        val presentedKeyBytes = pubKey.encoded
        if (presentedKeyBytes == null || presentedKeyBytes.isEmpty()) {
            throw CertificateException("Leaf certificate public key encoded bytes are null or empty")
        }

        val pinnedBytes = FileTransferClient.resolvePinnedKey(context, overridePinnedKey)

        if (pinnedBytes == null || pinnedBytes.isEmpty()) {
            throw CertificateException("No pinned Windows public key found. Refusing untrusted peer connection.")
        }

        if (!MessageDigest.isEqual(pinnedBytes, presentedKeyBytes)) {
            throw CertificateException("Certificate pinning failed: presented server public key does not match pinned identity.")
        }

        lastVerifiedCert = leaf
    }
}

object FileTransferClient {

    private val clientCache = ConcurrentHashMap<Int, OkHttpClient>()

    fun clearCache() {
        clientCache.clear()
    }

    fun resolveContext(providedContext: Context?): Context? {
        return providedContext
            ?: TetherLanService.instance
            ?: try { TetherApplication.instance } catch (_: Exception) { null }
    }

    fun resolvePinnedKey(providedContext: Context?, customPinnedKey: ByteArray?): ByteArray? {
        if (customPinnedKey != null && customPinnedKey.isNotEmpty()) {
            return customPinnedKey
        }

        val targetContext = resolveContext(providedContext)
        if (targetContext != null) {
            val engine = ProductionSecurityEngine()
            when (val pinResult = engine.getPinnedKeyResult(targetContext)) {
                is PinnedKeyResult.Present -> return pinResult.keyBytes
                is PinnedKeyResult.Corrupted -> {
                    throw IllegalStateException("Cannot resolve pinned key: stored pin is corrupted or inaccessible")
                }
                is PinnedKeyResult.Unprovisioned -> { /* Fall through to active peer key if connected */ }
            }
        }

        val service = TetherLanService.instance
        if (service != null &&
            (service.currentState == TransportState.READY || service.currentState == TransportState.AUTHENTICATED)) {
            return try {
                service.getActivePeerPublicKeyBytes()
            } catch (_: Exception) {
                null
            }
        }

        return null
    }

    private fun addAuthAndProofHeaders(
        builder: Request.Builder,
        token: String,
        context: Context?,
        customPinnedKey: ByteArray?
    ) {
        val timestampMs = System.currentTimeMillis().toString()
        val pinnedKey = resolvePinnedKey(context, customPinnedKey)
            ?: throw IllegalStateException("Cannot execute file transfer request: Windows host public key is not pinned or resolved.")

        val winSpkiBase64 = android.util.Base64.encodeToString(pinnedKey, android.util.Base64.NO_WRAP)
        val proofData = "$token:$timestampMs:$winSpkiBase64".toByteArray(Charsets.UTF_8)
        val signatureBytes = try {
            ProductionSecurityEngine().signWithIdentityKey(proofData)
        } catch (e: Exception) {
            throw IllegalStateException("Failed to sign request client proof with device identity key: ${e.message}", e)
        }
        val proofBase64 = android.util.Base64.encodeToString(signatureBytes, android.util.Base64.NO_WRAP)

        builder
            .header("Authorization", "Bearer $token")
            .header("X-Tether-Client-Proof", proofBase64)
            .header("X-Tether-Client-Timestamp", timestampMs)
            .header("X-Tether-Client-WinSpki", winSpkiBase64)
    }

    private fun matchesKeyType(keyType: String?): Boolean {
        if (keyType.isNullOrBlank()) return true
        val typeUpper = keyType.uppercase(Locale.US)
        return typeUpper.contains("EC") || typeUpper.contains("ECDSA")
    }

    fun getPinnedClient(context: Context?, customPinnedKey: ByteArray? = null, host: String? = null): OkHttpClient {
        val pinnedKey = resolvePinnedKey(context, customPinnedKey)
        val hostPart = host?.trim() ?: ""
        val cacheKey = (pinnedKey?.contentHashCode() ?: 0) * 31 + hostPart.hashCode()

        return clientCache.getOrPut(cacheKey) {
            val trustManager = TetherPinnedTrustManager(context, customPinnedKey)

            val customKeyManager = object : X509ExtendedKeyManager() {
                override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?): Array<String> {
                    return if (matchesKeyType(keyType)) arrayOf("TetherIdentity") else emptyArray()
                }

                override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?): String? {
                    val supportsEc = keyType == null || keyType.isEmpty() || keyType.any { matchesKeyType(it) }
                    return if (supportsEc) "TetherIdentity" else null
                }

                override fun chooseEngineClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, engine: SSLEngine?): String? {
                    val supportsEc = keyType == null || keyType.isEmpty() || keyType.any { matchesKeyType(it) }
                    return if (supportsEc) "TetherIdentity" else null
                }

                override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?): Array<String> = emptyArray()
                override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: Socket?): String? = null
                override fun chooseEngineServerAlias(keyType: String?, issuers: Array<out Principal>?, engine: SSLEngine?): String? = null

                override fun getCertificateChain(alias: String?): Array<X509Certificate>? {
                    return try {
                        val engine = ProductionSecurityEngine()
                        arrayOf(engine.getIdentityCertificate())
                    } catch (_: Exception) {
                        null
                    }
                }

                override fun getPrivateKey(alias: String?): PrivateKey? {
                    return try {
                        ProductionSecurityEngine().getIdentityPrivateKey()
                    } catch (_: Exception) {
                        null
                    }
                }
            }

            val sslContext = SSLContext.getInstance("TLS").apply {
                init(arrayOf<KeyManager>(customKeyManager), arrayOf<TrustManager>(trustManager), SecureRandom())
            }

            val hostnameVerifier = HostnameVerifier { _, session ->
                try {
                    val certs = session.peerCertificates
                    if (certs.isEmpty() || certs[0] !is X509Certificate) return@HostnameVerifier false
                    val leaf = certs[0] as X509Certificate
                    val resolvedKey = resolvePinnedKey(context, customPinnedKey)
                    if (resolvedKey == null || resolvedKey.isEmpty()) return@HostnameVerifier false
                    MessageDigest.isEqual(resolvedKey, leaf.publicKey.encoded)
                } catch (_: Exception) {
                    false
                }
            }

            val pinnerBuilder = CertificatePinner.Builder()
            if (pinnedKey != null && pinnedKey.isNotEmpty()) {
                val sha256 = MessageDigest.getInstance("SHA-256").digest(pinnedKey)
                val pinBase64 = android.util.Base64.encodeToString(sha256, android.util.Base64.NO_WRAP)
                val pin = "sha256/$pinBase64"
                if (hostPart.isNotEmpty()) {
                    pinnerBuilder.add(hostPart, pin)
                }
                pinnerBuilder.add("localhost", pin)
                pinnerBuilder.add("127.0.0.1", pin)
                pinnerBuilder.add("*.local", pin)
            }

            OkHttpClient.Builder()
                .sslSocketFactory(sslContext.socketFactory, trustManager)
                .hostnameVerifier(hostnameVerifier)
                .certificatePinner(pinnerBuilder.build())
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(60, TimeUnit.SECONDS)
                .writeTimeout(60, TimeUnit.SECONDS)
                .build()
        }
    }

    fun getStreamingClient(
        context: Context?,
        customPinnedKey: ByteArray? = null,
        host: String? = null
    ): OkHttpClient {
        val base = getPinnedClient(context, customPinnedKey, host)
        val pinnedKey = resolvePinnedKey(context, customPinnedKey)
            ?: throw IllegalStateException("Windows host public key must be pinned before initiating desktop streaming.")
        val sha256 = MessageDigest.getInstance("SHA-256").digest(pinnedKey)
        val pinBase64 = android.util.Base64.encodeToString(sha256, android.util.Base64.NO_WRAP)
        val pin = "sha256/$pinBase64"
        val hostPart = host?.trim() ?: ""

        val pinnerBuilder = CertificatePinner.Builder()
        if (hostPart.isNotEmpty()) {
            pinnerBuilder.add(hostPart, pin)
        }
        pinnerBuilder.add("localhost", pin)
        pinnerBuilder.add("127.0.0.1", pin)
        pinnerBuilder.add("*.local", pin)

        return base.newBuilder()
            .certificatePinner(pinnerBuilder.build())
            .readTimeout(0, TimeUnit.MILLISECONDS)
            .build()
    }

    fun openDesktopStream(
        hostIp: String,
        token: String,
        targetFps: Int,
        targetQuality: Int,
        windowId: Long?,
        context: Context?,
        customPinnedKey: ByteArray? = null
    ): Response {
        val client = getStreamingClient(context, customPinnedKey, hostIp)
        val urlBuilder = HttpUrl.Builder()
            .scheme("https")
            .host(hostIp)
            .port(TetherNetworkConstants.FILE_TRANSFER_PORT)
            .addPathSegment("api")
            .addPathSegment("desktop")
            .addPathSegment("stream")
            .addQueryParameter("fps", targetFps.toString())
            .addQueryParameter("quality", targetQuality.toString())

        if (windowId != null && windowId != 0L) {
            urlBuilder.addQueryParameter("windowId", windowId.toString())
        }

        val requestBuilder = Request.Builder().url(urlBuilder.build())
        addAuthAndProofHeaders(requestBuilder, token, context, customPinnedKey)
        return client.newCall(requestBuilder.build()).execute()
    }

    private inline fun <T> Call.executeWithDiagnostics(block: (Response) -> T): T {
        try {
            return execute().use(block)
        } catch (e: javax.net.ssl.SSLException) {
            val msg = e.message ?: ""
            if (msg.contains("I/O error during system call") || msg.contains("ssl=")) {
                throw Exception("File transfer TLS connection was reset by Windows server. Verify server identity trust and service status.", e)
            }
            throw Exception("File transfer TLS handshake failed: ${e.message}", e)
        } catch (e: java.net.SocketException) {
            throw Exception("File transfer socket error: ${e.message}", e)
        } catch (e: IOException) {
            throw Exception("File transfer network I/O error: ${e.message}", e)
        }
    }

    suspend fun listDirectory(
        hostIp: String,
        path: String?,
        token: String,
        context: Context? = null,
        customPinnedKey: ByteArray? = null
    ): List<FileNode> = withContext(Dispatchers.IO) {
        val client = getPinnedClient(context, customPinnedKey, hostIp)

        val urlBuilder = HttpUrl.Builder()
            .scheme("https")
            .host(hostIp)
            .port(TetherNetworkConstants.FILE_TRANSFER_PORT)
            .addPathSegment("api")
            .addPathSegment("fs")
            .addPathSegment("list")

        if (!path.isNullOrEmpty()) {
            urlBuilder.addQueryParameter("path", path)
        }

        val requestBuilder = Request.Builder().url(urlBuilder.build())
        addAuthAndProofHeaders(requestBuilder, token, context, customPinnedKey)

        client.newCall(requestBuilder.build()).executeWithDiagnostics { response ->
            if (!response.isSuccessful) {
                throw Exception("Failed to list directory: ${response.code} ${response.message}")
            }
            val responseBody = response.body?.string() ?: throw Exception("Empty response body")
            val jsonArray = JSONArray(responseBody)
            val result = mutableListOf<FileNode>()
            for (i in 0 until jsonArray.length()) {
                val obj = jsonArray.getJSONObject(i)
                result.add(
                    FileNode(
                        name = obj.getString("name"),
                        isDirectory = obj.getBoolean("isDirectory"),
                        size = obj.optLong("size", 0L),
                        modifiedMs = obj.optLong("lastModified", 0L),
                        path = obj.getString("path")
                    )
                )
            }
            result.sortedWith(compareBy({ !it.isDirectory }, { it.name.lowercase() }))
        }
    }

    fun queryDisplayName(context: Context, uri: Uri): String {
        if (uri.scheme == "content") {
            try {
                context.contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
                    if (cursor.moveToFirst()) {
                        val idx = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                        if (idx >= 0) {
                            val name = cursor.getString(idx)
                            if (!name.isNullOrBlank()) return name
                        }
                    }
                }
            } catch (_: Exception) {}
        }
        return uri.lastPathSegment?.substringAfterLast('/')?.ifBlank { null } ?: "file_${System.currentTimeMillis()}"
    }

    suspend fun downloadFile(
        hostIp: String,
        path: String,
        destUri: Uri,
        context: Context,
        token: String,
        customPinnedKey: ByteArray? = null,
        onProgress: ((bytesTransferred: Long, totalBytes: Long, speedBps: Long, etaSec: Long) -> Unit)? = null
    ) = withContext(Dispatchers.IO) {
        val client = getPinnedClient(context, customPinnedKey, hostIp)
        val resolvedFileName = path.substringAfterLast('\\').substringAfterLast('/').ifBlank { "downloaded_file" }
        val transferId = (System.currentTimeMillis() and 0x7FFFFFFF).toInt()

        val url = HttpUrl.Builder()
            .scheme("https")
            .host(hostIp)
            .port(TetherNetworkConstants.FILE_TRANSFER_PORT)
            .addPathSegment("api")
            .addPathSegment("fs")
            .addPathSegment("download")
            .addQueryParameter("path", path)
            .build()

        val requestBuilder = Request.Builder().url(url)
        addAuthAndProofHeaders(requestBuilder, token, context, customPinnedKey)

        try {
            client.newCall(requestBuilder.build()).executeWithDiagnostics { response ->
                if (!response.isSuccessful) {
                    throw Exception("Failed to download file: ${response.code} ${response.message}")
                }
                val body = response.body ?: throw Exception("Empty response body")
                val totalBytes = body.contentLength()
                val expectedHashHex = response.header("X-Tether-File-SHA512")?.trim()?.lowercase(Locale.US)

                val digest = MessageDigest.getInstance("SHA-512")
                val startTime = System.currentTimeMillis()
                var lastProgressTime = 0L
                var totalBytesRead = 0L

                context.contentResolver.openOutputStream(destUri)?.use { outputStream ->
                    body.byteStream().use { inputStream ->
                        val buffer = ByteArray(81920)
                        var bytesRead: Int
                        while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                            outputStream.write(buffer, 0, bytesRead)
                            digest.update(buffer, 0, bytesRead)
                            totalBytesRead += bytesRead

                            val now = System.currentTimeMillis()
                            if (now - lastProgressTime >= 250 || (totalBytes > 0 && totalBytesRead >= totalBytes)) {
                                lastProgressTime = now
                                val elapsedSec = (now - startTime).coerceAtLeast(1) / 1000.0
                                val speedBps = (totalBytesRead / elapsedSec).toLong()
                                val etaSec = if (speedBps > 0 && totalBytes > totalBytesRead) (totalBytes - totalBytesRead) / speedBps else 0L

                                onProgress?.invoke(totalBytesRead, totalBytes, speedBps, etaSec)
                                FileTransferNotificationManager.showProgress(
                                    context, transferId, resolvedFileName, false, totalBytesRead, totalBytes, speedBps, etaSec
                                )
                            }
                        }
                    }
                } ?: throw Exception("Could not open destination URI for writing")

                if (!expectedHashHex.isNullOrBlank()) {
                    val actualHashHex = digest.digest().joinToString("") { "%02x".format(it) }
                    if (!expectedHashHex.equals(actualHashHex, ignoreCase = true)) {
                        try { context.contentResolver.delete(destUri, null, null) } catch (_: Exception) {}
                        throw Exception("SHA-512 integrity check failed for downloaded file: expected $expectedHashHex, got $actualHashHex")
                    }
                }

                val savedDisplayPath = destUri.path?.substringAfterLast(':') ?: destUri.lastPathSegment ?: resolvedFileName
                FileTransferNotificationManager.showComplete(
                    context, transferId, resolvedFileName, false, destUri, savedDisplayPath
                )
            }
        } catch (e: Exception) {
            FileTransferNotificationManager.showError(
                context, transferId, resolvedFileName, false, e.message ?: "Download failed"
            )
            throw e
        }
    }

    suspend fun uploadFile(
        hostIp: String,
        sourceUri: Uri,
        destPath: String,
        context: Context,
        token: String,
        customPinnedKey: ByteArray? = null,
        onProgress: ((bytesTransferred: Long, totalBytes: Long, speedBps: Long, etaSec: Long) -> Unit)? = null
    ) = withContext(Dispatchers.IO) {
        val client = getPinnedClient(context, customPinnedKey, hostIp)
        val resolvedFileName = queryDisplayName(context, sourceUri)
        val transferId = (System.currentTimeMillis() and 0x7FFFFFFF).toInt()

        val effectiveDestPath = if (destPath.isBlank() || destPath.endsWith("\\") || destPath.endsWith("/")) {
            (destPath.trimEnd('\\', '/') + "\\" + resolvedFileName).trimStart('\\')
        } else {
            destPath
        }

        val url = HttpUrl.Builder()
            .scheme("https")
            .host(hostIp)
            .port(TetherNetworkConstants.FILE_TRANSFER_PORT)
            .addPathSegment("api")
            .addPathSegment("fs")
            .addPathSegment("upload")
            .addQueryParameter("path", effectiveDestPath)
            .build()

        val contentResolver = context.contentResolver
        val mimeType = contentResolver.getType(sourceUri) ?: "application/octet-stream"
        val fileSize = try {
            contentResolver.openFileDescriptor(sourceUri, "r")?.use { it.statSize } ?: -1L
        } catch (_: Exception) { -1L }

        val digest = MessageDigest.getInstance("SHA-512")
        val startTime = System.currentTimeMillis()
        var lastProgressTime = 0L
        var totalBytesRead = 0L

        val requestBody = object : RequestBody() {
            override fun contentType(): MediaType? = mimeType.toMediaTypeOrNull()

            override fun contentLength(): Long = fileSize

            override fun writeTo(sink: BufferedSink) {
                contentResolver.openInputStream(sourceUri)?.use { inputStream ->
                    val buffer = ByteArray(81920)
                    var read: Int
                    while (inputStream.read(buffer).also { read = it } != -1) {
                        sink.write(buffer, 0, read)
                        digest.update(buffer, 0, read)
                        totalBytesRead += read

                        val now = System.currentTimeMillis()
                        if (now - lastProgressTime >= 250 || (fileSize > 0 && totalBytesRead >= fileSize)) {
                            lastProgressTime = now
                            val elapsedSec = (now - startTime).coerceAtLeast(1) / 1000.0
                            val speedBps = (totalBytesRead / elapsedSec).toLong()
                            val etaSec = if (speedBps > 0 && fileSize > totalBytesRead) (fileSize - totalBytesRead) / speedBps else 0L

                            onProgress?.invoke(totalBytesRead, fileSize, speedBps, etaSec)
                            FileTransferNotificationManager.showProgress(
                                context, transferId, resolvedFileName, true, totalBytesRead, fileSize, speedBps, etaSec
                            )
                        }
                    }
                } ?: throw IOException("Could not open source URI for reading")
            }
        }

        // Pre-compute hash for upload header if stream supports reading
        val uploadDigest = MessageDigest.getInstance("SHA-512")
        try {
            contentResolver.openInputStream(sourceUri)?.use { stream ->
                val buf = ByteArray(81920)
                var r: Int
                while (stream.read(buf).also { r = it } != -1) {
                    uploadDigest.update(buf, 0, r)
                }
            }
        } catch (_: Exception) {}
        val fileHashHex = uploadDigest.digest().joinToString("") { "%02x".format(it) }

        val requestBuilder = Request.Builder()
            .url(url)
            .post(requestBody)
            .header("X-Tether-File-SHA512", fileHashHex)
            .header("X-Tether-File-Name", resolvedFileName)

        addAuthAndProofHeaders(requestBuilder, token, context, customPinnedKey)

        try {
            client.newCall(requestBuilder.build()).executeWithDiagnostics { response ->
                if (!response.isSuccessful) {
                    throw Exception("Failed to upload file: ${response.code} ${response.message}")
                }
                FileTransferNotificationManager.showComplete(
                    context, transferId, resolvedFileName, true, null, effectiveDestPath
                )
            }
        } catch (e: Exception) {
            FileTransferNotificationManager.showError(
                context, transferId, resolvedFileName, true, e.message ?: "Upload failed"
            )
            throw e
        }
    }

    suspend fun searchFiles(
        hostIp: String,
        path: String?,
        query: String,
        recursive: Boolean = true,
        token: String,
        context: Context? = null,
        customPinnedKey: ByteArray? = null
    ): List<FileNode> = withContext(Dispatchers.IO) {
        val client = getPinnedClient(context, customPinnedKey, hostIp)
        val urlBuilder = HttpUrl.Builder()
            .scheme("https")
            .host(hostIp)
            .port(TetherNetworkConstants.FILE_TRANSFER_PORT)
            .addPathSegment("api")
            .addPathSegment("fs")
            .addPathSegment("search")
            .addQueryParameter("query", query)
            .addQueryParameter("recursive", recursive.toString())

        if (!path.isNullOrEmpty()) {
            urlBuilder.addQueryParameter("path", path)
        }

        val requestBuilder = Request.Builder().url(urlBuilder.build())
        addAuthAndProofHeaders(requestBuilder, token, context, customPinnedKey)

        client.newCall(requestBuilder.build()).executeWithDiagnostics { response ->
            if (!response.isSuccessful) {
                throw Exception("Failed to search files: ${response.code} ${response.message}")
            }
            val responseBody = response.body?.string() ?: throw Exception("Empty response body")
            val jsonArray = JSONArray(responseBody)
            val result = mutableListOf<FileNode>()
            for (i in 0 until jsonArray.length()) {
                val obj = jsonArray.getJSONObject(i)
                result.add(
                    FileNode(
                        name = obj.getString("name"),
                        isDirectory = obj.getBoolean("isDirectory"),
                        size = obj.optLong("size", 0L),
                        modifiedMs = obj.optLong("lastModified", 0L),
                        path = obj.getString("path")
                    )
                )
            }
            result
        }
    }

    suspend fun renameFile(
        hostIp: String,
        path: String,
        newName: String,
        token: String,
        context: Context? = null,
        customPinnedKey: ByteArray? = null
    ): Boolean = withContext(Dispatchers.IO) {
        val client = getPinnedClient(context, customPinnedKey, hostIp)
        val url = HttpUrl.Builder()
            .scheme("https")
            .host(hostIp)
            .port(TetherNetworkConstants.FILE_TRANSFER_PORT)
            .addPathSegment("api")
            .addPathSegment("fs")
            .addPathSegment("rename")
            .build()

        val json = JSONObject().apply {
            put("path", path)
            put("newName", newName)
        }.toString()

        val body = json.toRequestBody("application/json; charset=utf-8".toMediaTypeOrNull())
        val requestBuilder = Request.Builder().url(url).post(body)
        addAuthAndProofHeaders(requestBuilder, token, context, customPinnedKey)

        client.newCall(requestBuilder.build()).executeWithDiagnostics { response ->
            response.isSuccessful
        }
    }

    suspend fun moveFile(
        hostIp: String,
        sourcePath: String,
        destinationPath: String,
        token: String,
        context: Context? = null,
        customPinnedKey: ByteArray? = null
    ): Boolean = withContext(Dispatchers.IO) {
        val client = getPinnedClient(context, customPinnedKey, hostIp)
        val url = HttpUrl.Builder()
            .scheme("https")
            .host(hostIp)
            .port(TetherNetworkConstants.FILE_TRANSFER_PORT)
            .addPathSegment("api")
            .addPathSegment("fs")
            .addPathSegment("move")
            .build()

        val json = JSONObject().apply {
            put("sourcePath", sourcePath)
            put("destinationPath", destinationPath)
        }.toString()

        val body = json.toRequestBody("application/json; charset=utf-8".toMediaTypeOrNull())
        val requestBuilder = Request.Builder().url(url).post(body)
        addAuthAndProofHeaders(requestBuilder, token, context, customPinnedKey)

        client.newCall(requestBuilder.build()).executeWithDiagnostics { response ->
            response.isSuccessful
        }
    }

    suspend fun deleteFile(
        hostIp: String,
        path: String,
        permanent: Boolean,
        token: String,
        context: Context? = null,
        customPinnedKey: ByteArray? = null
    ): Boolean = withContext(Dispatchers.IO) {
        val client = getPinnedClient(context, customPinnedKey, hostIp)
        val url = HttpUrl.Builder()
            .scheme("https")
            .host(hostIp)
            .port(TetherNetworkConstants.FILE_TRANSFER_PORT)
            .addPathSegment("api")
            .addPathSegment("fs")
            .addPathSegment("delete")
            .build()

        val json = JSONObject().apply {
            put("path", path)
            put("permanent", permanent)
        }.toString()

        val body = json.toRequestBody("application/json; charset=utf-8".toMediaTypeOrNull())
        val requestBuilder = Request.Builder().url(url).post(body)
        addAuthAndProofHeaders(requestBuilder, token, context, customPinnedKey)

        client.newCall(requestBuilder.build()).executeWithDiagnostics { response ->
            response.isSuccessful
        }
    }

    suspend fun createDirectory(
        hostIp: String,
        path: String,
        name: String,
        token: String,
        context: Context? = null,
        customPinnedKey: ByteArray? = null
    ): Boolean = withContext(Dispatchers.IO) {
        val client = getPinnedClient(context, customPinnedKey, hostIp)
        val url = HttpUrl.Builder()
            .scheme("https")
            .host(hostIp)
            .port(TetherNetworkConstants.FILE_TRANSFER_PORT)
            .addPathSegment("api")
            .addPathSegment("fs")
            .addPathSegment("mkdir")
            .build()

        val json = JSONObject().apply {
            put("path", path)
            put("name", name)
        }.toString()

        val body = json.toRequestBody("application/json; charset=utf-8".toMediaTypeOrNull())
        val requestBuilder = Request.Builder().url(url).post(body)
        addAuthAndProofHeaders(requestBuilder, token, context, customPinnedKey)

        client.newCall(requestBuilder.build()).executeWithDiagnostics { response ->
            response.isSuccessful
        }
    }

    suspend fun emptyRecycleBin(
        hostIp: String,
        token: String,
        context: Context? = null,
        customPinnedKey: ByteArray? = null
    ): Boolean = withContext(Dispatchers.IO) {
        val client = getPinnedClient(context, customPinnedKey, hostIp)
        val url = HttpUrl.Builder()
            .scheme("https")
            .host(hostIp)
            .port(TetherNetworkConstants.FILE_TRANSFER_PORT)
            .addPathSegment("api")
            .addPathSegment("fs")
            .addPathSegment("recycle-bin")
            .addPathSegment("empty")
            .build()

        val body = ByteArray(0).toRequestBody(null)
        val requestBuilder = Request.Builder().url(url).post(body)
        addAuthAndProofHeaders(requestBuilder, token, context, customPinnedKey)

        client.newCall(requestBuilder.build()).executeWithDiagnostics { response ->
            response.isSuccessful
        }
    }

    suspend fun fetchDesktopWindows(
        hostIp: String,
        token: String,
        context: Context? = null,
        customPinnedKey: ByteArray? = null
    ): List<DesktopWindow> = withContext(Dispatchers.IO) {
        val client = getPinnedClient(context, customPinnedKey, hostIp)
        val url = HttpUrl.Builder()
            .scheme("https")
            .host(hostIp)
            .port(TetherNetworkConstants.FILE_TRANSFER_PORT)
            .addPathSegment("api")
            .addPathSegment("desktop")
            .addPathSegment("windows")
            .build()

        val requestBuilder = Request.Builder().url(url)
        addAuthAndProofHeaders(requestBuilder, token, context, customPinnedKey)

        client.newCall(requestBuilder.build()).executeWithDiagnostics { response ->
            if (!response.isSuccessful) {
                return@executeWithDiagnostics emptyList<DesktopWindow>()
            }
            val responseBody = response.body?.string() ?: return@executeWithDiagnostics emptyList<DesktopWindow>()
            val jsonArray = JSONArray(responseBody)
            val result = mutableListOf<DesktopWindow>()
            for (i in 0 until jsonArray.length()) {
                val obj = jsonArray.getJSONObject(i)
                val hwnd = obj.optLong("hwnd", obj.optLong("id", obj.optLong("Id", 0L)))
                val title = obj.optString("title", obj.optString("Title", ""))
                val processName = obj.optString("processName", obj.optString("ProcessName", obj.optString("appName", "")))
                val processId = obj.optInt("processId", obj.optInt("ProcessId", obj.optInt("pid", obj.optInt("Pid", 0))))
                val width = obj.optInt("width", obj.optInt("Width", 0))
                val height = obj.optInt("height", obj.optInt("Height", 0))
                val iconB64 = obj.optString("iconB64", obj.optString("IconB64", "")).ifEmpty { null }
                result.add(
                    DesktopWindow(
                        hwnd = hwnd,
                        title = title,
                        processName = processName,
                        processId = processId,
                        width = width,
                        height = height,
                        iconB64 = iconB64
                    )
                )
            }
            result
        }
    }

    suspend fun fetchInstalledApps(
        hostIp: String,
        token: String,
        context: Context? = null,
        customPinnedKey: ByteArray? = null
    ): List<InstalledAppItem> = withContext(Dispatchers.IO) {
        val client = getPinnedClient(context, customPinnedKey, hostIp)
        val url = HttpUrl.Builder()
            .scheme("https")
            .host(hostIp)
            .port(TetherNetworkConstants.FILE_TRANSFER_PORT)
            .addPathSegment("api")
            .addPathSegment("apps")
            .addPathSegment("catalog")
            .build()

        val requestBuilder = Request.Builder().url(url)
        addAuthAndProofHeaders(requestBuilder, token, context, customPinnedKey)

        client.newCall(requestBuilder.build()).executeWithDiagnostics { response ->
            if (!response.isSuccessful) {
                return@executeWithDiagnostics emptyList<InstalledAppItem>()
            }
            val responseBody = response.body?.string() ?: return@executeWithDiagnostics emptyList<InstalledAppItem>()
            val jsonArray = JSONArray(responseBody)
            val result = mutableListOf<InstalledAppItem>()
            for (i in 0 until jsonArray.length()) {
                val obj = jsonArray.getJSONObject(i)
                val appPath = obj.optString("path", "").ifEmpty {
                    obj.optString("shortcutPath", obj.optString("ShortcutPath", ""))
                }
                val appName = obj.optString("name", obj.optString("Name", ""))
                val iconB64 = obj.optString("iconB64", obj.optString("IconB64", "")).ifEmpty { null }
                result.add(
                    InstalledAppItem(
                        name = appName,
                        path = appPath,
                        iconB64 = iconB64
                    )
                )
            }
            result
        }
    }

    suspend fun fetchScreenshotBytes(
        hostIp: String,
        windowId: Long = 0L,
        quality: Int = 75,
        token: String,
        context: Context? = null,
        customPinnedKey: ByteArray? = null
    ): ByteArray? = withContext(Dispatchers.IO) {
        val client = getPinnedClient(context, customPinnedKey, hostIp)
        val url = HttpUrl.Builder()
            .scheme("https")
            .host(hostIp)
            .port(TetherNetworkConstants.FILE_TRANSFER_PORT)
            .addPathSegment("api")
            .addPathSegment("desktop")
            .addPathSegment("screenshot")
            .addQueryParameter("windowId", windowId.toString())
            .addQueryParameter("quality", quality.toString())
            .build()

        val requestBuilder = Request.Builder().url(url)
        addAuthAndProofHeaders(requestBuilder, token, context, customPinnedKey)

        client.newCall(requestBuilder.build()).executeWithDiagnostics { response ->
            if (!response.isSuccessful) null else response.body?.bytes()
        }
    }
}
