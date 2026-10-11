package com.tether.phone

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build

object TetherNotificationChannels {
    const val CHANNEL_LAN_SERVICE = "tether_lan_channel"
    const val CHANNEL_UNLOCK_PROMPT = "tether_unlock_prompt"
    const val CHANNEL_POWER_EVENTS = "tether_power_events"

    fun createAllChannels(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return

        val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        // 1. Persistent Foreground Service Channel (Low importance)
        val serviceChannel = NotificationChannel(
            CHANNEL_LAN_SERVICE,
            context.getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = "Persistent connection state for Tether background service"
            setShowBadge(false)
        }

        // 2. High-Priority PC Unlock Prompt Channel (High importance, heads-up)
        val unlockPromptChannel = NotificationChannel(
            CHANNEL_UNLOCK_PROMPT,
            "PC Unlock Prompts",
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = "Heads-up notifications to quickly unlock your connected PC"
            lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            enableVibration(true)
            vibrationPattern = longArrayOf(0, 150, 100, 150)
            setShowBadge(true)
        }

        // 3. Power Events Channel (High importance)
        val powerChannel = NotificationChannel(
            CHANNEL_POWER_EVENTS,
            "Tether Power Events",
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = "Alerts when your PC powers off, sleeps, or locks"
            lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            enableVibration(true)
        }

        notificationManager.createNotificationChannels(
            listOf(serviceChannel, unlockPromptChannel, powerChannel)
        )
    }
}
