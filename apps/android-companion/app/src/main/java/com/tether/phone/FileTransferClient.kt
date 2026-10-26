package com.tether.phone

import android.content.Context
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okio.BufferedSink
import okio.source
import org.json.JSONArray
import java.net.Socket
import java.security.MessageDigest
import java.security.Principal
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
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
        throw CertificateException("Client authentication is not supported on this endpoint")
    }

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        verifyPinning(chain)
    }

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) {
        throw CertificateException("Client authentication is not supported on this endpoint")
    }

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) {
        verifyPinning(chain)
    }

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) {
        throw CertificateException("Client authentication is not supported on this endpoint")
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
        return providedContext ?: try { TetherApplication.instance } catch (_: Exception) { null }
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
        val winSpkiBase64 = if (pinnedKey != null && pinnedKey.isNotEmpty()) {
            android.util.Base64.encodeToString(pinnedKey, android.util.Base64.NO_WRAP)
        } else ""

        val proofData = "$token:$timestampMs:$winSpkiBase64".toByteArray(Charsets.UTF_8)
        val signatureBytes = try {
            ProductionSecurityEngine().signWithIdentityKey(proofData)
        } catch (_: Exception) {
            byteArrayOf()
        }
        val proofBase64 = android.util.Base64.encodeToString(signatureBytes, android.util.Base64.NO_WRAP)

        builder
            .header("Authorization", "Bearer $token")
            .header("X-Tether-Client-Proof", proofBase64)
            .header("X-Tether-Client-Timestamp", timestampMs)
    }

    fun getPinnedClient(context: Context?, customPinnedKey: ByteArray? = null): OkHttpClient {
        val pinnedKey = resolvePinnedKey(context, customPinnedKey)
        val cacheKey = pinnedKey?.contentHashCode() ?: 0

        return clientCache.getOrPut(cacheKey) {
            val trustManager = TetherPinnedTrustManager(context, customPinnedKey)

            val customKeyManager = object : X509ExtendedKeyManager() {
                override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?): Array<String> = arrayOf("TetherIdentity")
                override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?): String = "TetherIdentity"
                override fun chooseEngineClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, engine: SSLEngine?): String = "TetherIdentity"
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

        client.newCall(requestBuilder.build()).execute().use { response ->
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

        client.newCall(requestBuilder.build()).execute().use { response ->
            if (!response.isSuccessful) {
                throw Exception("Failed to download file: ${response.code} ${response.message}")
            }
            val body = response.body ?: throw Exception("Empty response body")

            context.contentResolver.openOutputStream(destUri)?.use { outputStream ->
                body.byteStream().use { inputStream ->
                    inputStream.copyTo(outputStream)
                }
            } ?: throw Exception("Could not open destination URI for writing")
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

        val requestBody = object : RequestBody() {
            override fun contentType(): MediaType? = mimeType.toMediaTypeOrNull()

            override fun writeTo(sink: BufferedSink) {
                contentResolver.openInputStream(sourceUri)?.use { inputStream ->
                    inputStream.source().use { source ->
                        sink.writeAll(source)
                    }
                }
            }
        }

        val requestBuilder = Request.Builder().url(url).post(requestBody)
        addAuthAndProofHeaders(requestBuilder, token, context, customPinnedKey)

        client.newCall(requestBuilder.build()).execute().use { response ->
            if (!response.isSuccessful) {
                throw Exception("Failed to upload file: ${response.code} ${response.message}")
            }
        }
    }
}
