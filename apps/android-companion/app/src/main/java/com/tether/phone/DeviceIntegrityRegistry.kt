package com.tether.phone

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import java.io.File
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

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
            0,
        ) == 0
        if (usbDebuggingDisabled) finalScore += 10
        val appIntegrityValid = verifyAppSignatureIntegrity()
        if (appIntegrityValid) finalScore += 10
        val km = context.getSystemService(KeyguardManager::class.java)
        val secureLockscreenEnabled = km?.isDeviceSecure ?: false
        if (secureLockscreenEnabled) finalScore += 10
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

    private fun checkRootStatus(): Boolean {
        val tags = Build.TAGS
        if ((tags != null) && tags.contains("test-keys")) return true
        val commonPaths = arrayOf(
            "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", 
            "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su", 
            "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su",
            "/system/bin/.ext/.su", "/system/usr/we-need-root/su-backup",
            "/system/xbin/mu", "/system/bin/magisk", "/sbin/.magisk",
        )
        for (path in commonPaths) if (File(path).exists()) return true

        try {
            val process = Runtime.getRuntime().exec(arrayOf("which", "su"))
            val reader = process.inputStream.bufferedReader()
            if (reader.readLine() != null) return true
        } catch (_: Exception) {}

        if (Build.TYPE.contains("userdebug") || Build.TYPE.contains("eng")) return true

        return false
    }

    /**
     * Optional Play Integrity verdict hook for production device attestation.
     */
    @Suppress("unused")
    fun fetchPlayIntegrityVerdict(): Boolean {
        // TODO: Integrate Google Play Integrity API for hardware-backed remote attestation
        return true
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

            // SHA-256 fingerprint of the app signing public key
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

            // SECURITY FIX: Enforce public key pin without debug/emulator bypasses
            computedHash == targetCertificatePin
        } catch (_: Exception) { 
            false 
        }
    }
}
