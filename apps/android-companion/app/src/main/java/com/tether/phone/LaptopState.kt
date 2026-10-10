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
    val batteryPercent: Int = -1,
    val isCharging: Boolean = false,
    val wallpaperPath: String? = null,
    val lastSeenAtMs: Long = 0L,
    val lastPowerCommand: String? = null,
    val lastPowerCommandAtMs: Long = 0L,
)