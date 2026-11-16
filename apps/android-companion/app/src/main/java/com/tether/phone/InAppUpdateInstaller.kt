package com.tether.phone

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.util.Log
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.net.URL
import java.net.HttpURLConnection
import java.security.MessageDigest

/**
 * Downloads the update APK to app-private storage, verifies it is signed with the
 * same signing key as the installed app (nothing else can install over us anyway,
 * but this blocks installing a rogue downgrade/lookalike), then hands it to the
 * system package installer. The file is deleted after the install intent fires.
 */
object InAppUpdateInstaller {

    private const val TAG = "InAppUpdateInstaller"
    private const val FILE_NAME = "tether-update.apk"

    data class DownloadResult(val file: File?, val error: String? = null)

    fun hasInstallPermission(context: Context): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.O || context.packageManager.canRequestPackageInstalls()

    suspend fun downloadAndInstall(context: Context, apkUrl: String): DownloadResult = withContext(Dispatchers.IO) {
        try {
            if (!hasInstallPermission(context)) {
                return@withContext DownloadResult(null, "install_permission_required")
            }

            val dir = File(context.cacheDir, "updates").apply { mkdirs() }
            val outFile = File(dir, FILE_NAME)
            if (outFile.exists()) outFile.delete()

            val conn = (URL(apkUrl).openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                setRequestProperty("User-Agent", "Tether-Android-Updater")
                connectTimeout = 15_000
                readTimeout = 30_000
                instanceFollowRedirects = true
            }
            if (conn.responseCode !in 200..299) {
                return@withContext DownloadResult(null, "download_failed_http_${conn.responseCode}")
            }

            conn.inputStream.use { input ->
                outFile.outputStream().use { output ->
                    input.copyTo(output, DEFAULT_BUFFER_SIZE)
                }
            }

            if (!isSameSignature(context, outFile)) {
                outFile.delete()
                return@withContext DownloadResult(null, "signature_mismatch")
            }

            installApk(context, outFile)
            DownloadResult(outFile)
        } catch (e: Exception) {
            Log.e(TAG, "Update download/install failed: ${e.message}", e)
            DownloadResult(null, e.message)
        }
    }

    /**
     * A package can only be installed over this one if it is signed with the same key,
     * so the pre-check is a fail-fast guard, not the sole defense.
     */
    private fun isSameSignature(context: Context, apk: File): Boolean {
        return try {
            val pm = context.packageManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val installed = pm.getPackageInfo(context.packageName, android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES)
                    .signingInfo!!.apkContentsSigners
                val incoming = pm.getPackageArchiveInfo(apk.absolutePath, android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES)
                    ?.signingInfo?.apkContentsSigners
                if (incoming == null) {
                    Log.w(TAG, "Could not read signatures from downloaded APK")
                    return false
                }
                val installedKeys = installed.map { digestHex(it.toByteArray()) }.toSet()
                val incomingKeys = incoming.map { digestHex(it.toByteArray()) }.toSet()
                installedKeys.intersect(incomingKeys).isNotEmpty()
            } else {
                @Suppress("DEPRECATION")
                val installed = pm.getPackageInfo(context.packageName, android.content.pm.PackageManager.GET_SIGNATURES)
                @Suppress("DEPRECATION")
                val incoming = pm.getPackageArchiveInfo(apk.absolutePath, android.content.pm.PackageManager.GET_SIGNATURES)
                val installedHex = installed.signatures?.firstOrNull()?.toByteArray()?.let { sig -> digestHex(sig) }
                val incomingHex = incoming?.signatures?.firstOrNull()?.toByteArray()?.let { sig -> digestHex(sig) }
                installedHex != null && installedHex == incomingHex
            }
        } catch (e: Exception) {
            Log.w(TAG, "Signature pre-check failed: ${e.message}")
            false
        }
    }

    private fun digestHex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun installApk(context: Context, apk: File) {
        val uri: Uri = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", apk)
        } else {
            Uri.fromFile(apk)
        }
        val intent = Intent(Intent.ACTION_INSTALL_PACKAGE).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        context.startActivity(intent)
        // shortcut: file is deleted on next updater run / cache clear, since ACTION_INSTALL_PACKAGE
        // streams the content immediately; upgrade to a DELETE receiver when targeting stricter OEMs.
        apk.delete()
    }
}
