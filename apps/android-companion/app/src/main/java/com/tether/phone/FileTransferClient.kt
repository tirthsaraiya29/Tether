package com.tether.phone

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.asRequestBody
import okio.BufferedSink
import okio.source
import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

data class FileNode(
    val name: String,
    val isDirectory: Boolean,
    val size: Long,
    val modifiedMs: Long,
    val path: String
)

object FileTransferClient {
    private val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    })

    private val sslContext = SSLContext.getInstance("SSL").apply {
        init(null, trustAllCerts, SecureRandom())
    }

    private val client = OkHttpClient.Builder()
        .sslSocketFactory(sslContext.socketFactory, trustAllCerts[0] as X509TrustManager)
        .hostnameVerifier { _, _ -> true }
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(60, TimeUnit.SECONDS)
        .writeTimeout(60, TimeUnit.SECONDS)
        .build()

    suspend fun listDirectory(hostIp: String, path: String?, token: String): List<FileNode> = withContext(Dispatchers.IO) {
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

        val request = Request.Builder()
            .url(urlBuilder.build())
            .header("Authorization", "Bearer $token")
            .build()

        client.newCall(request).execute().use { response ->
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
            // Sort directories first, then alphabetically
            result.sortedWith(compareBy({ !it.isDirectory }, { it.name.lowercase() }))
        }
    }

    suspend fun downloadFile(hostIp: String, path: String, destUri: Uri, context: Context, token: String) = withContext(Dispatchers.IO) {
        val url = HttpUrl.Builder()
            .scheme("https")
            .host(hostIp)
            .port(37124)
            .addPathSegment("api")
            .addPathSegment("fs")
            .addPathSegment("download")
            .addQueryParameter("path", path)
            .build()

        val request = Request.Builder()
            .url(url)
            .header("Authorization", "Bearer $token")
            .build()

        client.newCall(request).execute().use { response ->
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

    suspend fun uploadFile(hostIp: String, sourceUri: Uri, destPath: String, context: Context, token: String) = withContext(Dispatchers.IO) {
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

        val request = Request.Builder()
            .url(url)
            .header("Authorization", "Bearer $token")
            .post(requestBody)
            .build()

        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                throw Exception("Failed to upload file: ${response.code} ${response.message}")
            }
        }
    }
}
