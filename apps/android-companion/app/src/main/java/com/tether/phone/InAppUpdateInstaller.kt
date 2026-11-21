package com.tether.phone

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.os.Build
import android.util.Log
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
    const val ACTION_PACKAGE_INSTALL_STATUS = "com.tether.phone.ACTION_PACKAGE_INSTALL_STATUS"

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
    @Suppress("DEPRECATION")
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
        val packageInstaller = context.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
            setAppPackageName(context.packageName)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_REQUIRED)
            }
        }
        val sessionId = packageInstaller.createSession(params)
        packageInstaller.openSession(sessionId).use { session ->
            session.openWrite("tether-update", 0, apk.length()).use { out ->
                apk.inputStream().use { input ->
                    input.copyTo(out)
                }
                session.fsync(out)
            }
            val intent = Intent(context, PackageInstallStatusReceiver::class.java).apply {
                action = ACTION_PACKAGE_INSTALL_STATUS
                setPackage(context.packageName)
            }
            val flags = PendingIntent.FLAG_UPDATE_CURRENT or (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) PendingIntent.FLAG_MUTABLE else 0)
            val pendingIntent = PendingIntent.getBroadcast(
                context,
                sessionId,
                intent,
                flags
            )
            session.commit(pendingIntent.intentSender)
        }
        apk.delete()
    }
}
