package com.tether.phone

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
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
    private const val KEY_CACHED_ETAG = "cached_github_etag"
    private const val KEY_SNOOZE_UNTIL_MS = "update_snooze_until_ms"
    private const val KEY_SNOOZED_VERSION = "update_snoozed_version"

    /**
     * Checks if the app is running in a Debug configuration or development environment.
     * In debug environments, all update checks are completely bypassed.
     */
    fun isDebugMode(context: Context): Boolean {
        if (BuildConfig.DEBUG) return true
        val isDebuggable = (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        return isDebuggable
    }

    suspend fun fetchLatestRelease(context: Context, force: Boolean = false): UpdateInfo? = withContext(Dispatchers.IO) {
        if (!force && isDebugMode(context)) {
            Log.d(TAG, "Debug build detected - background update checks bypassed.")
            return@withContext null
        }

        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val cachedEtag = prefs.getString(KEY_CACHED_ETAG, null)

        try {
            // nosemgrep: kotlin.lang.security.android.missing-certificate-pinning, java.android.security.certificate-pinning
            val conn = (URL(LATEST_RELEASE_API).openConnection() as HttpsURLConnection).apply {
                requestMethod = "GET"
                setRequestProperty("Accept", "application/vnd.github+json")
                setRequestProperty("User-Agent", "Tether-Android-UpdateChecker")
                if (!force && !cachedEtag.isNullOrBlank()) {
                    setRequestProperty("If-None-Match", cachedEtag)
                }
                connectTimeout = 8_000
                readTimeout = 8_000
            }

            if (conn.responseCode == HttpsURLConnection.HTTP_NOT_MODIFIED) {
                Log.d(TAG, "GitHub API returned 304 Not Modified - using cached release info.")
                return@withContext getCachedUpdateInfo(context)
            }

            if (conn.responseCode != HttpsURLConnection.HTTP_OK) {
                Log.w(TAG, "GitHub API returned ${conn.responseCode}")
                return@withContext null
            }

            val newEtag = conn.getHeaderField("ETag")
            if (!newEtag.isNullOrBlank()) {
                prefs.edit { putString(KEY_CACHED_ETAG, newEtag) }
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

            val info = UpdateInfo(
                latestVersion = tagName,
                releaseUrl = htmlUrl,
                releaseNotes = bodyText,
                apkDownloadUrl = apkUrl,
            )

            cacheUpdateInfo(context, info)
            info
        } catch (e: Exception) {
            Log.e(TAG, "Failed to fetch latest release: ${e.message}", e)
            null
        }
    }

    /**
     * Compares dotted version strings (e.g. "1.1.5" vs "1.1.6").
     * Returns true when [remote] is strictly newer than [local].
     */
    fun isNewerVersion(local: String, remote: String): Boolean {
        val localClean = local.trimStart('v', 'V').substringBefore('-')
        val remoteClean = remote.trimStart('v', 'V').substringBefore('-')
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

    fun isSnoozed(context: Context, remoteVersion: String): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val snoozeUntilMs = prefs.getLong(KEY_SNOOZE_UNTIL_MS, 0L)
        val snoozedVersion = prefs.getString(KEY_SNOOZED_VERSION, null) ?: return false

        // If a newer critical version dropped than the one snoozed, bypass snooze!
        if (isNewerVersion(snoozedVersion, remoteVersion)) {
            return false
        }

        return System.currentTimeMillis() < snoozeUntilMs
    }

    fun snooze(context: Context, version: String, hours: Int) {
        val snoozeUntil = System.currentTimeMillis() + (hours * 3600L * 1000L)
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit {
            putLong(KEY_SNOOZE_UNTIL_MS, snoozeUntil)
            putString(KEY_SNOOZED_VERSION, version)
        }

        // Schedule an alarm to notify user when snooze expires
        try {
            val alarmManager = context.getSystemService(Context.ALARM_SERVICE) as? AlarmManager
            val intent = Intent(context, UpdateSnoozeReceiver::class.java).apply {
                action = UpdateSnoozeReceiver.ACTION_SNOOZE_EXPIRED
                putExtra(UpdateSnoozeReceiver.EXTRA_VERSION, version)
            }
            val pendingIntent = PendingIntent.getBroadcast(
                context,
                1001,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )

            alarmManager?.setAndAllowWhileIdle(
                AlarmManager.RTC_WAKEUP,
                snoozeUntil,
                pendingIntent,
            )
            Log.i(TAG, "Update snoozed for $hours hours until $snoozeUntil")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to schedule snooze alarm: ${e.message}")
        }
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
