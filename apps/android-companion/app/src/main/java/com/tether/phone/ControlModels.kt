package com.tether.phone

/**
 * Data structures for Tether PC Control Features
 */

data class MediaState(
    val title: String = "No Active Session",
    val artist: String = "Windows Media Engine",
    val album: String = "",
    val isPlaying: Boolean = false,
    val durationMs: Long = 0L,
    val positionMs: Long = 0L,
    val artworkBase64: String? = null
)

data class AppInfo(
    val id: String,
    val name: String,
    val category: String,
    val iconName: String = "default"
)

val defaultWindowsApplications = listOf(
    AppInfo("calculator", "Calculator", "System", "calculator"),
    AppInfo("explorer", "File Explorer", "System", "folder"),
    AppInfo("chrome", "Google Chrome", "Internet", "public"),
    AppInfo("edge", "Microsoft Edge", "Internet", "public"),
    AppInfo("spotify", "Spotify", "Media", "music_note"),
    AppInfo("terminal", "Windows Terminal", "Developer", "terminal"),
    AppInfo("taskmgr", "Task Manager", "System", "analytics"),
    AppInfo("notepad", "Notepad", "Productivity", "description"),
    AppInfo("settings", "Windows Settings", "System", "settings"),
    AppInfo("vscode", "VS Code", "Developer", "code")
)
