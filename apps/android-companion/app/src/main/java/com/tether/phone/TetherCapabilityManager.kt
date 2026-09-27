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

    private var negotiatedCapabilities: Set<TetherCapability> = emptySet()

    fun negotiateCapabilities(peerCapsString: String): Set<TetherCapability> {
        val peerCaps = peerCapsString.split(",")
            .asSequence()
            .mapNotNull { TetherCapability.fromScopeName(it.trim()) }
            .toSet()

        negotiatedCapabilities = DEFAULT_ANDROID_CAPABILITIES.intersect(peerCaps)
        Log.i(TAG, "Negotiated capabilities: ${getNegotiatedCapabilitiesString()}")
        return negotiatedCapabilities
    }

    fun isCapabilityGranted(capability: TetherCapability): Boolean {
        return negotiatedCapabilities.contains(capability)
    }

    fun canExecuteCommand(command: String): Boolean {
        val requiredCap = when (command.lowercase()) {
            "shutdown", "reboot", "sleep", "halt" -> TetherCapability.POWER_ELEVATED
            "cmd", "powershell", "powershell7", "wsl", "bash" -> TetherCapability.TERMINAL
            "copy", "paste", "clipboard" -> TetherCapability.CLIPBOARD
            "file_transfer", "file_list" -> TetherCapability.FILES
            "volume_up", "volume_down", "brightness_up", "brightness_down", "media_play", "media_pause" -> TetherCapability.MEDIA
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
