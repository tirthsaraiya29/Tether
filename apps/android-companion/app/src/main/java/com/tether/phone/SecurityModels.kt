package com.tether.phone

import androidx.annotation.StringRes
import androidx.compose.ui.graphics.Color
import com.tether.phone.ui.theme.*

enum class TrustVerificationStep {
    NOT_IN_PANIC,
    DEVICE_CREDENTIAL,
    BIOMETRIC_FINGERPRINT
}

enum class TrustState {
    UNPAIRED,
    PAIRING_REQUESTED,
    PAIRED,
    REPAIRING,
    PAIRING_DENIED,
    KEY_MISMATCH
}

enum class AppScreen {
    FILE_TRANSFER,
    TELEMETRY_DASHBOARD,
    SECURITY_SETTINGS,
    LAPTOP_CONTROL,
    SYSTEM_APPS,
    PAIRING,
    REMOTE_INPUT,
    PERMISSIONS,
    REMOTE_DESKTOP,
    ADVANCED_AUDIO,
    REMOTE_TERMINAL,
    CLIPBOARD,
    NOTIFICATIONS,
    WINDOWS_ADMIN,
    APP_MANAGEMENT,
    AUTOMATION
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

data class DesktopWindow(
    val hwnd: Long = 0L,
    val title: String = "",
    val processName: String = "",
    val processId: Int = 0,
    val width: Int = 0,
    val height: Int = 0
)

data class AppAudioSessionItem(
    val pid: Int = 0,
    val processName: String = "",
    val volumePercent: Int = 50,
    val isMuted: Boolean = false
)

data class AudioDeviceItem(
    val id: String = "",
    val name: String = "",
    val isDefault: Boolean = false,
    val isInput: Boolean = false
)

data class MediaPlaybackState(
    val title: String = "",
    val artist: String = "",
    val album: String = "",
    val isPlaying: Boolean = false,
    val position: Long = 0L,
    val duration: Long = 0L,
    val thumbnail: String = ""
)

data class TerminalTab(
    val id: String = "",
    val shellType: String = "powershell",
    val workingDir: String = ""
)

data class SyncedNotification(
    val id: Long = 0L,
    val app: String = "",
    val title: String = "",
    val body: String = "",
    val timestamp: Long = 0L,
    val source: String = "WINDOWS"
)

data class DiskUsageItem(
    val name: String = "",
    val volumeLabel: String = "",
    val totalGb: Double = 0.0,
    val freeGb: Double = 0.0,
    val format: String = ""
)

data class NetworkAdapterItem(
    val name: String = "",
    val description: String = "",
    val type: String = "",
    val bytesReceived: Long = 0L,
    val bytesSent: Long = 0L,
    val speedMbps: Long = 0L
)

data class AdminTelemetry(
    val cpuUsage: Int = 0,
    val totalRamMb: Long = 0L,
    val availRamMb: Long = 0L,
    val ramUsagePct: Int = 0,
    val disks: List<DiskUsageItem> = emptyList(),
    val networks: List<NetworkAdapterItem> = emptyList()
)

data class BatteryHealthState(
    val designCapacityMwh: Double = 0.0,
    val fullChargeCapacityMwh: Double = 0.0,
    val wearLevelPct: Int = 0,
    val cycleCount: Int = 0
)

data class PowerPlanItem(
    val guid: String = "",
    val name: String = "",
    val isActive: Boolean = false
)

data class PrinterItem(
    val name: String = "",
    val port: String = "",
    val status: String = "",
    val jobsCount: Int = 0
)

data class UsbItem(
    val id: String = "",
    val name: String = "",
    val status: String = "OK"
)

data class WindowsServiceItem(
    val name: String = "",
    val displayName: String = "",
    val status: String = "",
    val canStop: Boolean = false
)

data class WindowsUpdateState(
    val pendingCount: Int = 0,
    val isAvailable: Boolean = false,
    val titles: List<String> = emptyList()
)

data class InstalledAppItem(
    val name: String = "",
    val path: String = ""
)

data class RunningWindowItem(
    val hwnd: Long = 0L,
    val title: String = "",
    val processName: String = "",
    val pid: Int = 0,
    val isMinimized: Boolean = false,
    val isMaximized: Boolean = false
)

data class AutomationWorkflowItem(
    val id: String = "",
    val name: String = "",
    val isEnabled: Boolean = true,
    val scheduleType: String = "manual",
    val scheduleValue: String = "",
    val conditionType: String = "none",
    val conditionValue: String = "",
    val actions: List<String> = emptyList(),
    val lastExecutedMs: Long = 0L,
    val lastStatus: String = "NEVER"
)
