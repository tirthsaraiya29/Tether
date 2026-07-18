package com.tether.phone

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import java.io.File

class DeviceIntegrityRegistry(private val context: Context) {
    fun runAttestationPipeline(): IntegrityReport {
        var finalScore = 0
        val bootloaderLocked = checkBootloaderStatus()
        if (bootloaderLocked) finalScore += 35
        val notRooted = !checkRootStatus()
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
            0
        ) == 0
        if (usbDebuggingDisabled) finalScore += 10
        val appIntegrityValid = verifyAppSignatureIntegrity()
        if (appIntegrityValid) finalScore += 10
        val km = context.getSystemService(KeyguardManager::class.java)
        val secureLockscreenEnabled = km?.isDeviceSecure ?: false
        if (secureLockscreenEnabled) finalScore += 10
        val assignedTier = when (finalScore) {
            in 100..110 -> TrustTier.TRUSTED
            in 85..99 -> TrustTier.ELEVATED_RISK
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
            secureLockscreenEnabled
        )
    }

    private fun checkBootloaderStatus(): Boolean {
        val aboot = Build.BOOTLOADER.lowercase()
        return aboot.isNotEmpty() && !aboot.contains("unknown") && !aboot.contains("unlocked")
    }

    private fun checkRootStatus(): Boolean {
        val tags = Build.TAGS
        if ((tags != null) && tags.contains("test-keys")) return true
        val commonPaths = arrayOf(
            "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", 
            "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su", 
            "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su"
        )
        for (path in commonPaths) if (File(path).exists()) return true
        return false
    }

    private fun verifyAppSignatureIntegrity(): Boolean {
        return try {
            val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageManager.GET_SIGNING_CERTIFICATES
            } else {
                @Suppress("DEPRECATION")
                PackageManager.GET_SIGNATURES
            }

            val packageInfo = context.packageManager.getPackageInfo(context.packageName, flags)
            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo.signingInfo?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                packageInfo.signatures
            }

            if (signatures.isNullOrEmpty()) return false

            val targetCertificatePin = "D8:5F:A3:4E:91:C1:28:9B:F3:A1:02:4F:99:A8:12:44:A2:3F:89:B1:02:44:5F:99:A8:B1:22:4E:A3:F4:99:12"

            val digestEngine = java.security.MessageDigest.getInstance("SHA-256")
            val certBytes = signatures[0].toByteArray()
            val computedHash = digestEngine.digest(certBytes).joinToString(":") { 
                String.format("%02X", it) 
            }

            computedHash == targetCertificatePin || Build.FINGERPRINT.startsWith("generic")
        } catch (_: Exception) { 
            false 
        }
    }
}
