package com.tether.phone

import android.content.Context
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okio.BufferedSink
import org.json.JSONArray
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

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        // Client cert validation is handled at middleware level via proof headers
    }

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        verifyPinning(chain)
    }

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) {
        // Client cert validation is handled at middleware level via proof headers
    }

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) {
        verifyPinning(chain)
    }

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) {
        // Client cert validation is handled at middleware level via proof headers
    }

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) {
        verifyPinning(chain)
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()

    fun verifyPinning(chain: Array<out X509Certificate>?) {
        if (chain.isNullOrEmpty()) {
            throw CertificateException("Server certificate chain is null or empty")
        }
        val leaf = chain[0]
        leaf.checkValidity()

        val pinnedBytes = FileTransferClient.resolvePinnedKey(context, overridePinnedKey)

        if (pinnedBytes == null || pinnedBytes.isEmpty()) {
            throw CertificateException("No pinned Windows public key found. Refusing untrusted peer connection.")
        }

        val presentedKeyBytes = leaf.publicKey.encoded
        if (!MessageDigest.isEqual(pinnedBytes, presentedKeyBytes)) {
            throw CertificateException("Certificate pinning failed: presented server public key does not match pinned identity.")
        }
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
        val storedKey = targetContext?.let {
            try {
                ProductionSecurityEngine().getPinnedKeyDecrypted(it)
            } catch (_: Exception) {
                null
            }
        }
        if (storedKey != null && storedKey.isNotEmpty()) {
            return storedKey
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

    fun getPinnedClient(context: Context?, customPinnedKey: ByteArray? = null): OkHttpClient {
        val pinnedKey = resolvePinnedKey(context, customPinnedKey)
        val cacheKey = pinnedKey?.contentHashCode() ?: 0

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

            OkHttpClient.Builder()
                .sslSocketFactory(sslContext.socketFactory, trustManager)
                .hostnameVerifier(hostnameVerifier)
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(60, TimeUnit.SECONDS)
                .writeTimeout(60, TimeUnit.SECONDS)
                .build()
        }
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
        val client = getPinnedClient(context, customPinnedKey)

        val urlBuilder = HttpUrl.Builder()
            .scheme("https")
            .host(hostIp)
            .port(37124)
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

    suspend fun downloadFile(
        hostIp: String,
        path: String,
        destUri: Uri,
        context: Context,
        token: String,
        customPinnedKey: ByteArray? = null
    ) = withContext(Dispatchers.IO) {
        val client = getPinnedClient(context, customPinnedKey)

        val url = HttpUrl.Builder()
            .scheme("https")
            .host(hostIp)
            .port(37124)
            .addPathSegment("api")
            .addPathSegment("fs")
            .addPathSegment("download")
            .addQueryParameter("path", path)
            .build()

        val requestBuilder = Request.Builder().url(url)
        addAuthAndProofHeaders(requestBuilder, token, context, customPinnedKey)

        client.newCall(requestBuilder.build()).executeWithDiagnostics { response ->
            if (!response.isSuccessful) {
                throw Exception("Failed to download file: ${response.code} ${response.message}")
            }
            val body = response.body ?: throw Exception("Empty response body")
            val expectedHashHex = response.header("X-Tether-File-SHA512")?.trim()?.lowercase(Locale.US)

            val digest = MessageDigest.getInstance("SHA-512")
            context.contentResolver.openOutputStream(destUri)?.use { outputStream ->
                body.byteStream().use { inputStream ->
                    val buffer = ByteArray(81920)
                    var bytesRead: Int
                    while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                        outputStream.write(buffer, 0, bytesRead)
                        digest.update(buffer, 0, bytesRead)
                    }
                }
            } ?: throw Exception("Could not open destination URI for writing")

            if (!expectedHashHex.isNullOrBlank()) {
                val actualHashHex = digest.digest().joinToString("") { "%02x".format(it) }
                if (!expectedHashHex.equals(actualHashHex, ignoreCase = true)) {
                    throw Exception("SHA-512 integrity check failed for downloaded file: expected $expectedHashHex, got $actualHashHex")
                }
            }
        }
    }

    suspend fun uploadFile(
        hostIp: String,
        sourceUri: Uri,
        destPath: String,
        context: Context,
        token: String,
        customPinnedKey: ByteArray? = null
    ) = withContext(Dispatchers.IO) {
        val client = getPinnedClient(context, customPinnedKey)

        val url = HttpUrl.Builder()
            .scheme("https")
            .host(hostIp)
            .port(37124)
            .addPathSegment("api")
            .addPathSegment("fs")
            .addPathSegment("upload")
            .addQueryParameter("path", destPath)
            .build()

        val contentResolver = context.contentResolver
        val mimeType = contentResolver.getType(sourceUri) ?: "application/octet-stream"

        val digest = MessageDigest.getInstance("SHA-512")
        val requestBody = object : RequestBody() {
            override fun contentType(): MediaType? = mimeType.toMediaTypeOrNull()

            override fun writeTo(sink: BufferedSink) {
                contentResolver.openInputStream(sourceUri)?.use { inputStream ->
                    val buffer = ByteArray(81920)
                    var read: Int
                    while (inputStream.read(buffer).also { read = it } != -1) {
                        sink.write(buffer, 0, read)
                        digest.update(buffer, 0, read)
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

        addAuthAndProofHeaders(requestBuilder, token, context, customPinnedKey)

        client.newCall(requestBuilder.build()).executeWithDiagnostics { response ->
            if (!response.isSuccessful) {
                throw Exception("Failed to upload file: ${response.code} ${response.message}")
            }
        }
    }
}
