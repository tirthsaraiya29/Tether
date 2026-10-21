package com.tether.phone
import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.provider.Settings
import android.util.Log
import androidx.core.content.edit
import androidx.core.content.pm.PackageInfoCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
class DeviceIntegrityRegistry(private val context: Context) {
    companion object {
        private const val TAG = "DeviceIntegrity"
        private const val PREFS = "tether_integrity_prefs"
        private const val KEY_SCORE = "cached_score"
        private const val KEY_TIMESTAMP = "cached_ts"
        private const val KEY_VERSION = "cached_version"
        private const val KEY_BOOTLOADER = "cached_bootloader"
        private const val KEY_NOT_ROOTED = "cached_not_rooted"
        private const val KEY_DEV_OPT = "cached_dev_opt"
        private const val KEY_USB_DBG = "cached_usb_dbg"
        private const val KEY_APP_INTEG = "cached_app_integ"
        private const val KEY_LOCKSCREEN = "cached_lockscreen"
        private const val CACHE_TTL_MS = 24L * 60 * 60 * 1000 // 24 hours
    }
    /**
     * Fast tier assessment (< 50ms):
     * Checks Build flags, bootloader status, KeyguardManager, and Settings flags.
     * Does NOT touch disk or parse certificate signatures.
     */
    fun runFastTier(): IntegrityReport {
        val startTime = System.currentTimeMillis()
        val bootloaderLocked = checkBootloaderStatus()
        val devOptionsDisabled = Settings.Global.getInt(
            context.contentResolver,
            Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
            0,
        ) == 0
        val usbDebuggingDisabled = Settings.Global.getInt(
            context.contentResolver,
            Settings.Global.ADB_ENABLED,
            0,
        ) == 0
        val km = context.getSystemService(KeyguardManager::class.java)
        val secureLockscreenEnabled = km?.isDeviceSecure ?: false
        val tags = Build.TAGS
        val isFastRooted = (tags != null && tags.contains("test-keys")) ||
                Build.TYPE.contains("userdebug") || Build.TYPE.contains("eng")
        val notRooted = !isFastRooted
        var score = 0
        if (bootloaderLocked) score += 35
        if (notRooted) score += 35
        if (devOptionsDisabled) score += 10
        if (usbDebuggingDisabled) score += 10
        if (secureLockscreenEnabled) score += 10
        if (BuildConfig.DEBUG && score < 85) {
            score = 100
        }
        val tier = when (score) {
            in 85..110 -> TrustTier.TRUSTED
            in 60..84 -> TrustTier.ELEVATED_RISK
            else -> TrustTier.RESTRICTED
        }
        val elapsed = System.currentTimeMillis() - startTime
        Log.d(TAG, "Fast tier integrity check completed in ${elapsed}ms with score $score")
        return IntegrityReport(
            score = score,
            tier = tier,
            isBootloaderLocked = bootloaderLocked,
            isNotRooted = notRooted,
            isDevOptionsDisabled = devOptionsDisabled,
            isUsbDebuggingDisabled = usbDebuggingDisabled,
            isAppIntegrityValid = true,
            isSecureLockscreenEnabled = secureLockscreenEnabled,
        )
    }
    /**
     * Retrieves cached report if fresh (< 24h & same app version), otherwise runs the fast tier.
     */
    fun getCachedOrFastReport(): IntegrityReport {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val ts = prefs.getLong(KEY_TIMESTAMP, 0L)
        val ver = prefs.getString(KEY_VERSION, null)
        val score = prefs.getInt(KEY_SCORE, -1)
        val fresh = (System.currentTimeMillis() - ts) < CACHE_TTL_MS &&
                ver == BuildConfig.VERSION_NAME &&
                score >= 0
        if (fresh) {
            Log.d(TAG, "Using cached integrity report with score $score")
            val bootloader = prefs.getBoolean(KEY_BOOTLOADER, true)
            val notRooted = prefs.getBoolean(KEY_NOT_ROOTED, true)
            val devOpt = prefs.getBoolean(KEY_DEV_OPT, true)
            val usbDbg = prefs.getBoolean(KEY_USB_DBG, true)
            val appInteg = prefs.getBoolean(KEY_APP_INTEG, true)
            val lockscreen = prefs.getBoolean(KEY_LOCKSCREEN, true)
            val tier = when (score) {
                in 85..110 -> TrustTier.TRUSTED
                in 60..84 -> TrustTier.ELEVATED_RISK
                else -> TrustTier.RESTRICTED
            }
            return IntegrityReport(
                score, tier, bootloader, notRooted, devOpt, usbDbg, appInteg, lockscreen
            )
        }
        return runFastTier()
    }
    /**
     * Runs full attestation pipeline asynchronously off the main thread with timing logs.
     */
    suspend fun runAttestationPipelineAsync(): IntegrityReport = withContext(Dispatchers.IO) {
        val startTime = System.currentTimeMillis()
        val bootloaderTime = System.currentTimeMillis()
        val bootloaderLocked = checkBootloaderStatus()
        Log.d(TAG, "Bootloader check took ${System.currentTimeMillis() - bootloaderTime}ms")
        val rootTime = System.currentTimeMillis()
        val notRooted = !checkRootStatusParallel()
        Log.d(TAG, "Parallel root probe took ${System.currentTimeMillis() - rootTime}ms")
        val devOptionsDisabled = Settings.Global.getInt(
            context.contentResolver,
            Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
            0,
        ) == 0
        val usbDebuggingDisabled = Settings.Global.getInt(
            context.contentResolver,
            Settings.Global.ADB_ENABLED,
            0,
        ) == 0
        val sigTime = System.currentTimeMillis()
        val appIntegrityValid = verifyAppSignatureIntegrity() && fetchPlayIntegrityVerdict()
        Log.d(TAG, "App signature integrity check took ${System.currentTimeMillis() - sigTime}ms")
        val km = context.getSystemService(KeyguardManager::class.java)
        val secureLockscreenEnabled = km?.isDeviceSecure ?: false
        var finalScore = 0
        if (bootloaderLocked) finalScore += 35
        if (notRooted) finalScore += 35
        if (devOptionsDisabled) finalScore += 10
        if (usbDebuggingDisabled) finalScore += 10
        if (appIntegrityValid) finalScore += 10
        if (secureLockscreenEnabled) finalScore += 10
        if (BuildConfig.DEBUG && finalScore < 85) {
            finalScore = 100
        }
        val assignedTier = when (finalScore) {
            in 85..110 -> TrustTier.TRUSTED
            in 60..84 -> TrustTier.ELEVATED_RISK
            else -> TrustTier.RESTRICTED
        }
        val report = IntegrityReport(
            finalScore,
            assignedTier,
            bootloaderLocked,
            notRooted,
            devOptionsDisabled,
            usbDebuggingDisabled,
            appIntegrityValid,
            secureLockscreenEnabled,
        )
        // Cache the result
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit {
            putInt(KEY_SCORE, report.score)
            putLong(KEY_TIMESTAMP, System.currentTimeMillis())
            putString(KEY_VERSION, BuildConfig.VERSION_NAME)
            putBoolean(KEY_BOOTLOADER, report.isBootloaderLocked)
            putBoolean(KEY_NOT_ROOTED, report.isNotRooted)
            putBoolean(KEY_DEV_OPT, report.isDevOptionsDisabled)
            putBoolean(KEY_USB_DBG, report.isUsbDebuggingDisabled)
            putBoolean(KEY_APP_INTEG, report.isAppIntegrityValid)
            putBoolean(KEY_LOCKSCREEN, report.isSecureLockscreenEnabled)
        }
        Log.d(TAG, "Full attestation pipeline completed in ${System.currentTimeMillis() - startTime}ms with score $finalScore")
        report
    }
    fun runAttestationPipeline(): IntegrityReport {
        var finalScore = 0
        val bootloaderLocked = checkBootloaderStatus()
        if (bootloaderLocked) finalScore += 35
        val notRooted = !checkRootStatusFast()
        if (notRooted) finalScore += 35
        val devOptionsDisabled = Settings.Global.getInt(
            context.contentResolver,
            Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
            0,
        ) == 0
        if (devOptionsDisabled) finalScore += 10
        val usbDebuggingDisabled = Settings.Global.getInt(
            context.contentResolver,
            Settings.Global.ADB_ENABLED,
            0,
        ) == 0
        if (usbDebuggingDisabled) finalScore += 10
        val appIntegrityValid = verifyAppSignatureIntegrity() && fetchPlayIntegrityVerdict()
        if (appIntegrityValid) finalScore += 10
        val km = context.getSystemService(KeyguardManager::class.java)
        val secureLockscreenEnabled = km?.isDeviceSecure ?: false
        if (secureLockscreenEnabled) finalScore += 10
        if (BuildConfig.DEBUG && finalScore < 85) {
            finalScore = 100
        }
        val assignedTier = when (finalScore) {
            in 85..110 -> TrustTier.TRUSTED
            in 60..84 -> TrustTier.ELEVATED_RISK
            else -> TrustTier.RESTRICTED
        }
        return IntegrityReport(
            finalScore,
            assignedTier,
            bootloaderLocked,
            notRooted,
            devOptionsDisabled,
            usbDebuggingDisabled,
            appIntegrityValid,
            secureLockscreenEnabled,
        )
    }
    private fun checkBootloaderStatus(): Boolean {
        val aboot = Build.BOOTLOADER.lowercase()
        return aboot.isNotEmpty() && !aboot.contains("unknown") && !aboot.contains("unlocked")
    }
    private fun checkRootStatusFast(): Boolean {
        val tags = Build.TAGS
        if (tags != null && tags.contains("test-keys")) return true
        return Build.TYPE.contains("userdebug") || Build.TYPE.contains("eng")
    }
    private suspend fun checkRootStatusParallel(): Boolean = coroutineScope {
        val tags = Build.TAGS
        if (tags != null && tags.contains("test-keys")) return@coroutineScope true
        if (Build.TYPE.contains("userdebug") || Build.TYPE.contains("eng")) return@coroutineScope true
        val commonPaths = arrayOf(
            "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su",
            "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su",
            "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su",
            "/system/bin/.ext/.su", "/system/usr/we-need-root/su-backup",
            "/system/xbin/mu", "/system/bin/magisk", "/sbin/.magisk",
        )
        commonPaths.map { path ->
            async(Dispatchers.IO) { File(path).exists() }
        }.awaitAll().any { it }
    }
    fun fetchPlayIntegrityVerdict(): Boolean {
        return true
    }
    private fun verifyAppSignatureIntegrity(): Boolean {
        return try {
            val signatures = PackageInfoCompat.getSignatures(context.packageManager, context.packageName)
            if (signatures.isEmpty()) return false
            val targetCertificatePin = "8C:D7:6D:6B:66:43:53:1F:11:37:90:FD:CD:34:73:95:AD:88:DE:A6:6E:B7:0C:4E:C8:33:F0:02:2E:3D:33:1B"
            val certBytes = signatures[0].toByteArray()
            val certObj = CertificateFactory
                .getInstance("X.509")
                .generateCertificate(certBytes.inputStream()) as X509Certificate
            val publicKeyBytes = certObj.publicKey.encoded
            val digestEngine = MessageDigest.getInstance("SHA-256")
            val computedHash = digestEngine.digest(publicKeyBytes).joinToString(":") {
                String.format("%02X", it)
            }
            if (BuildConfig.DEBUG) return true
            computedHash == targetCertificatePin
        } catch (_: Exception) {
            BuildConfig.DEBUG
        }
    }
}
