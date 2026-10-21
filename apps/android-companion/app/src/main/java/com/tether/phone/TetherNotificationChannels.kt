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
    const val CHANNEL_UPDATES = "tether_updates"
    fun createAllChannels(context: Context) {
        val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val channelsToCreate = mutableListOf<NotificationChannel>()
        if (notificationManager.getNotificationChannel(CHANNEL_LAN_SERVICE) == null) {
            channelsToCreate.add(
                NotificationChannel(
                    CHANNEL_LAN_SERVICE,
                    context.getString(R.string.notification_channel_name),
                    NotificationManager.IMPORTANCE_LOW,
                ).apply {
                    description = "Persistent connection state for Tether background service"
                    setShowBadge(false)
                }
            )
        }
        if (notificationManager.getNotificationChannel(CHANNEL_UNLOCK_PROMPT) == null) {
            channelsToCreate.add(
                NotificationChannel(
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
            )
        }
        if (notificationManager.getNotificationChannel(CHANNEL_POWER_EVENTS) == null) {
            channelsToCreate.add(
                NotificationChannel(
                    CHANNEL_POWER_EVENTS,
                    "Tether Power Events",
                    NotificationManager.IMPORTANCE_HIGH,
                ).apply {
                    description = "Alerts when your PC powers off, sleeps, or locks"
                    lockscreenVisibility = Notification.VISIBILITY_PUBLIC
                    enableVibration(true)
                }
            )
        }
        if (notificationManager.getNotificationChannel(CHANNEL_PAIRING_PROMPT) == null) {
            channelsToCreate.add(
                NotificationChannel(
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
            )
        }
        if (notificationManager.getNotificationChannel(CHANNEL_UPDATES) == null) {
            channelsToCreate.add(
                NotificationChannel(
                    CHANNEL_UPDATES,
                    "Tether App Updates",
                    NotificationManager.IMPORTANCE_DEFAULT,
                ).apply {
                    description = "Notifications when a new version of Tether is available"
                    setShowBadge(true)
                }
            )
        }
        if (channelsToCreate.isNotEmpty()) {
            notificationManager.createNotificationChannels(channelsToCreate)
        }
    }
}
