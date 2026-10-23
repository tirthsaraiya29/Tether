package com.tether.phone

import android.util.Log

enum class TetherCapability(val scopeName: String, val isElevated: Boolean) {
    CLIPBOARD("CLIPBOARD", false),
    FILES("FILES", false),
    NOTIFICATIONS("NOTIFICATIONS", false),
    MEDIA("MEDIA", false),
    TERMINAL("TERMINAL", true),
    POWER_ELEVATED("POWER_ELEVATED", true);

    companion object {
        fun fromScopeName(name: String): TetherCapability? {
            return entries.firstOrNull { it.scopeName.equals(name, ignoreCase = true) }
        }
    }
}

class TetherCapabilityManager {

    companion object {
        private const val TAG = "TetherCapabilityManager"

        val DEFAULT_ANDROID_CAPABILITIES = setOf(
            TetherCapability.CLIPBOARD,
            TetherCapability.FILES,
            TetherCapability.NOTIFICATIONS,
            TetherCapability.MEDIA,
            TetherCapability.TERMINAL,
            TetherCapability.POWER_ELEVATED,
        )
    }

    private var negotiatedCapabilities: Set<TetherCapability> = DEFAULT_ANDROID_CAPABILITIES

    fun negotiateCapabilities(peerCapsString: String): Set<TetherCapability> {
        if (peerCapsString.isBlank()) {
            Log.i(TAG, "Peer advertised no explicit capability restrictions. Defaulting to standard capabilities.")
            negotiatedCapabilities = DEFAULT_ANDROID_CAPABILITIES
            return negotiatedCapabilities
        }
        val peerCaps = peerCapsString.split(",")
            .asSequence()
            .mapNotNull { TetherCapability.fromScopeName(it.trim()) }
            .toSet()

        negotiatedCapabilities = DEFAULT_ANDROID_CAPABILITIES.intersect(peerCaps)
        Log.i(TAG, "Negotiated capabilities: ${getNegotiatedCapabilitiesString()}")
        if (!isCapabilityGranted(TetherCapability.MEDIA)) {
            Log.w(TAG, "WARNING: MEDIA capability is missing from negotiated set! Volume and media commands will be blocked.")
        }
        if (!isCapabilityGranted(TetherCapability.POWER_ELEVATED)) {
            Log.w(TAG, "WARNING: POWER_ELEVATED capability is missing from negotiated set! Power commands (shutdown, reboot, lock) will be blocked.")
        }
        return negotiatedCapabilities
    }

    fun isCapabilityGranted(capability: TetherCapability): Boolean {
        return negotiatedCapabilities.contains(capability)
    }

    fun canExecuteCommand(command: String): Boolean {
        val cmdLower = command.lowercase()
        val requiredCap = when {
            cmdLower in setOf("shutdown", "reboot", "sleep", "halt", "lock_now", "unlock", "lock") -> TetherCapability.POWER_ELEVATED
            cmdLower in setOf("cmd", "powershell", "powershell7", "wsl", "bash") -> TetherCapability.TERMINAL
            cmdLower in setOf("copy", "paste", "clipboard") -> TetherCapability.CLIPBOARD
            cmdLower in setOf("file_transfer", "file_list") -> TetherCapability.FILES
            (cmdLower in setOf("volume_up", "volume_down", "volume_mute", "volume_get", "vol_get", "get_volume", "set_volume", "brightness_up", "brightness_down", "bright_up", "bright_down", "brightness_get", "bright_get", "get_brightness", "set_brightness")) ||
                cmdLower.startsWith("volume_set:") || cmdLower.startsWith("set_volume:") || cmdLower.startsWith("vol_set:") ||
                cmdLower.startsWith("brightness_set:") || cmdLower.startsWith("set_brightness:") || cmdLower.startsWith("bright_set:") -> TetherCapability.MEDIA
            else -> TetherCapability.MEDIA
        }

        val isGranted = isCapabilityGranted(requiredCap)
        if (!isGranted) {
            Log.w(TAG, "Command execution denied for '$command': missing required capability ${requiredCap.scopeName} (isElevated=${requiredCap.isElevated})")
        }
        return isGranted
    }

    fun getNegotiatedCapabilitiesString(): String {
        return negotiatedCapabilities.joinToString(",") { it.scopeName }
    }
}