package com.tether.phone

import androidx.annotation.StringRes
import androidx.compose.ui.graphics.Color
import com.tether.phone.ui.theme.*

enum class TrustVerificationStep {
    NOT_IN_PANIC,
    DEVICE_CREDENTIAL,
    BIOMETRIC_FINGERPRINT
}

enum class AppScreen {
    TELEMETRY_DASHBOARD,
    SECURITY_SETTINGS,
    LAPTOP_CONTROL,
    PAIRING
}

enum class TrustTier(@param:StringRes val labelRes: Int, val color: Color) {
    TRUSTED(R.string.tier_trusted, IntegrityGreen),
    ELEVATED_RISK(R.string.tier_elevated_risk, MatrixGold),
    RESTRICTED(R.string.tier_restricted, AlertRed)
}

data class IntegrityReport(
    val score: Int,
    val tier: TrustTier,
    val isBootloaderLocked: Boolean,
    val isNotRooted: Boolean,
    val isDevOptionsDisabled: Boolean,
    val isUsbDebuggingDisabled: Boolean,
    val isAppIntegrityValid: Boolean,
    val isSecureLockscreenEnabled: Boolean,
)
