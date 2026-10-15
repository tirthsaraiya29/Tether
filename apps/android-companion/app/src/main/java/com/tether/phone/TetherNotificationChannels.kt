package com.tether.phone

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context

object TetherNotificationChannels {
    const val CHANNEL_LAN_SERVICE = "tether_lan_channel"
    const val CHANNEL_UNLOCK_PROMPT = "tether_unlock_prompt"
    const val CHANNEL_POWER_EVENTS = "tether_power_events"
    const val CHANNEL_PAIRING_PROMPT = "tether_pairing_prompt"

    fun createAllChannels(context: Context) {
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

        // 4. Pairing Requests Channel (High importance, heads-up)
        val pairingChannel = NotificationChannel(
            CHANNEL_PAIRING_PROMPT,
            "Tether Pairing Requests",
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = "Heads-up notifications to pair with your Windows PC"
            lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            enableVibration(true)
            vibrationPattern = longArrayOf(0, 200, 100, 200)
            setShowBadge(true)
        }

        notificationManager.createNotificationChannels(
            listOf(serviceChannel, unlockPromptChannel, powerChannel, pairingChannel)
        )
    }
}
