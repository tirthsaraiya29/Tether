package com.tether.phone

import android.content.Context
import android.util.Log
import androidx.core.content.edit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.URL
import javax.net.ssl.HttpsURLConnection

data class UpdateInfo(
    val latestVersion: String,
    val releaseUrl: String,
    val releaseNotes: String,
    val apkDownloadUrl: String?,
)

object UpdateChecker {

    private const val TAG = "UpdateChecker"
    private const val OWNER = "tirthsaraiya29"
    private const val REPO = "Tether"
    private const val LATEST_RELEASE_API = "https://api.github.com/repos/$OWNER/$REPO/releases/latest"

    private const val PREFS_NAME = "tether_update_prefs"
    private const val KEY_CACHED_VERSION = "cached_latest_version"
    private const val KEY_CACHED_RELEASE_URL = "cached_release_url"
    private const val KEY_CACHED_RELEASE_NOTES = "cached_release_notes"
    private const val KEY_CACHED_APK_URL = "cached_apk_url"

    suspend fun fetchLatestRelease(): UpdateInfo? = withContext(Dispatchers.IO) {
        try {
            // nosemgrep: kotlin.lang.security.android.missing-certificate-pinning, java.android.security.certificate-pinning
            val conn = (URL(LATEST_RELEASE_API).openConnection() as HttpsURLConnection).apply {
                requestMethod = "GET"
                setRequestProperty("Accept", "application/vnd.github+json")
                setRequestProperty("User-Agent", "Tether-Android-UpdateChecker")
                connectTimeout = 10_000
                readTimeout = 10_000
            }

            if (conn.responseCode != HttpsURLConnection.HTTP_OK) {
                Log.w(TAG, "GitHub API returned ${conn.responseCode}")
                return@withContext null
            }

            val body = conn.inputStream.bufferedReader().use { it.readText() }
            val json = JSONObject(body)

            val tagName = json.optString("tag_name", "").trimStart('v', 'V')
            val htmlUrl = json.optString("html_url", "")
            val bodyText = json.optString("body", "")

            // Find the first .apk asset
            val assets = json.optJSONArray("assets")
            var apkUrl: String? = null
            if (assets != null) {
                for (i in 0 until assets.length()) {
                    val asset = assets.optJSONObject(i) ?: continue
                    val name = asset.optString("name", "")
                    if (name.endsWith(".apk", ignoreCase = true)) {
                        apkUrl = if (asset.has("browser_download_url")) asset.optString("browser_download_url") else null
                        break
                    }
                }
            }

            UpdateInfo(
                latestVersion = tagName,
                releaseUrl = htmlUrl,
                releaseNotes = bodyText,
                apkDownloadUrl = apkUrl,
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to fetch latest release: ${e.message}", e)
            null
        }
    }

    /**
     * Compares dotted version strings (e.g. "2.0.1" vs "2.1.0").
     * Returns true when [remote] is strictly newer than [local].
     */
    fun isNewerVersion(local: String, remote: String): Boolean {
        val localClean = local.trimStart('v', 'V')
        val remoteClean = remote.trimStart('v', 'V')
        val localParts = localClean.split(".").mapNotNull { it.toIntOrNull() }
        val remoteParts = remoteClean.split(".").mapNotNull { it.toIntOrNull() }
        val maxLen = maxOf(localParts.size, remoteParts.size)
        for (i in 0 until maxLen) {
            val l = localParts.getOrElse(i) { 0 }
            val r = remoteParts.getOrElse(i) { 0 }
            if (r > l) return true
            if (r < l) return false
        }
        return false
    }

    fun cacheUpdateInfo(context: Context, info: UpdateInfo) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit {
            putString(KEY_CACHED_VERSION, info.latestVersion)
            putString(KEY_CACHED_RELEASE_URL, info.releaseUrl)
            putString(KEY_CACHED_RELEASE_NOTES, info.releaseNotes)
            putString(KEY_CACHED_APK_URL, info.apkDownloadUrl)
        }
    }

    fun getCachedUpdateInfo(context: Context): UpdateInfo? {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val version = prefs.getString(KEY_CACHED_VERSION, null) ?: return null
        val releaseUrl = prefs.getString(KEY_CACHED_RELEASE_URL, "") ?: ""
        val releaseNotes = prefs.getString(KEY_CACHED_RELEASE_NOTES, "") ?: ""
        val apkUrl = prefs.getString(KEY_CACHED_APK_URL, null)
        return UpdateInfo(
            latestVersion = version,
            releaseUrl = releaseUrl,
            releaseNotes = releaseNotes,
            apkDownloadUrl = apkUrl,
        )
    }
}
