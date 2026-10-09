package com.tether.phone

enum class LaptopPowerState {
    UNKNOWN,
    CONNECTED_UNLOCKED,
    CONNECTED_LOCKED,
    DISCONNECTED,
    RESTARTING,
    SHUTTING_DOWN,
    POWERED_OFF,
}

data class LaptopTelemetry(
    val powerState: LaptopPowerState = LaptopPowerState.UNKNOWN,
    val batteryPercent: Int = -1,       // -1 = unknown
    val isCharging: Boolean = false,
    val wallpaperPath: String? = null,  // Path to local saved wallpaper file
    val lastSeenAtMs: Long = 0L,
    val lastPowerCommand: String? = null, // "shutdown" | "reboot" | "sleep" | null
    val lastPowerCommandAtMs: Long = 0L,
)
