package com.tether.phone

import android.app.Notification
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat

object UnlockPromptNotifier {

    const val UNLOCK_NOTIFICATION_ID = 2001
    private const val BRAND_COLOR = 0xFF0F766E.toInt() // Deep Teal (#0F766E)

    /**
     * Posts or updates the high-priority "Unlock your PC?" notification.
     * Uses a deterministic notification ID [UNLOCK_NOTIFICATION_ID] so new connections
     * collapse and update existing prompts rather than stacking.
     */
    fun showUnlockPrompt(context: Context, peerDeviceName: String) {
        val safePeerName = peerDeviceName.ifBlank { "your PC" }

        // PendingIntent for "Unlock" action
        val unlockIntent = Intent(context, UnlockActionReceiver::class.java).apply {
            action = UnlockActionReceiver.ACTION_UNLOCK
            putExtra(UnlockActionReceiver.EXTRA_PEER_NAME, safePeerName)
        }
        // PendingIntent.FLAG_IMMUTABLE is required on API 31+ (Android 12+) to prevent
        // unauthorized apps from modifying intent contents. FLAG_UPDATE_CURRENT ensures
        // updated extras (like peer name) overwrite any existing pending intent.
        val unlockPendingIntent = PendingIntent.getBroadcast(
            context,
            101,
            unlockIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        // PendingIntent for "Dismiss" action
        val dismissIntent = Intent(context, UnlockActionReceiver::class.java).apply {
            action = UnlockActionReceiver.ACTION_DISMISS
        }
        val dismissPendingIntent = PendingIntent.getBroadcast(
            context,
            102,
            dismissIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val notification = NotificationCompat.Builder(context, TetherNotificationChannels.CHANNEL_UNLOCK_PROMPT)
            .setContentTitle("Unlock your PC?")
            .setContentText("Tether is connected to $safePeerName.")
            .setSmallIcon(R.drawable.ic_shortcut_unlock)
            .setColor(BRAND_COLOR)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setDefaults(Notification.DEFAULT_ALL)
            .setAutoCancel(true)
            .setOngoing(false)
            // "Unlock" action button
            .addAction(
                R.drawable.ic_shortcut_unlock,
                "Unlock",
                unlockPendingIntent,
            )
            // "Dismiss" action button
            .addAction(
                android.R.drawable.ic_menu_close_clear_cancel,
                "Dismiss",
                dismissPendingIntent,
            )
            // Sliding away the notification triggers dismiss action
            .setDeleteIntent(dismissPendingIntent)
            .build()

        try {
            NotificationManagerCompat.from(context).notify(UNLOCK_NOTIFICATION_ID, notification)
        } catch (e: SecurityException) {
            android.util.Log.w("UnlockPromptNotifier", "Cannot post notification: POST_NOTIFICATIONS permission missing")
        }
    }

    /**
     * Instantly removes any active unlock prompt notification when the TLS session drops
     * or when an unlock/dismiss action completes.
     */
    fun cancelUnlockPrompt(context: Context) {
        NotificationManagerCompat.from(context).cancel(UNLOCK_NOTIFICATION_ID)
    }
}
