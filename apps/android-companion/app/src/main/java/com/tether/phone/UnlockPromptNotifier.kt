package com.tether.phone

import android.app.Notification
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat

object UnlockPromptNotifier {

    const val UNLOCK_NOTIFICATION_ID = 2001

    // LiquidCyan (#00E5FF) - Tether's signature brand accent color
    private const val LIQUID_CYAN_ACCENT = 0xFF00E5FF.toInt()

    /**
     * Posts or updates the high-priority "Unlock PC" notification.
     * Styled to match Tether's signature cyan accent, terminology, and industrial UI tone.
     * Uses deterministic ID [UNLOCK_NOTIFICATION_ID] so new connections update in place.
     */
    fun showUnlockPrompt(context: Context, peerDeviceName: String) {
        val safePeerName = peerDeviceName.ifBlank { "Connected PC" }

        // PendingIntent for "UNLOCK PC" action
        val unlockIntent = Intent(context, UnlockActionReceiver::class.java).apply {
            action = UnlockActionReceiver.ACTION_UNLOCK
            putExtra(UnlockActionReceiver.EXTRA_PEER_NAME, safePeerName)
        }
        val unlockPendingIntent = PendingIntent.getBroadcast(
            context,
            101,
            unlockIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        // PendingIntent for "DISMISS" action
        val dismissIntent = Intent(context, UnlockActionReceiver::class.java).apply {
            action = UnlockActionReceiver.ACTION_DISMISS
        }
        val dismissPendingIntent = PendingIntent.getBroadcast(
            context,
            102,
            dismissIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val contentPendingIntent = PendingIntent.getActivity(
            context,
            100,
            Intent(context, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val notification = NotificationCompat.Builder(context, TetherNotificationChannels.CHANNEL_UNLOCK_PROMPT)
            .setContentTitle("Unlock $safePeerName")
            .setContentText("TLS 1.3 session established. Tap to authorize unlock.")
            .setStyle(
                NotificationCompat.BigTextStyle()
                    .setBigContentTitle("Unlock $safePeerName")
                    .bigText("TLS 1.3 session established with $safePeerName. Tap UNLOCK PC below or open Tether to manage your session.")
                    .setSummaryText("TETHER • SECURE LINK")
            )
            .setSubText("TETHER • SECURE LINK")
            .setSmallIcon(R.drawable.ic_shortcut_unlock)
            .setColor(LIQUID_CYAN_ACCENT)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setDefaults(Notification.DEFAULT_ALL)
            .setAutoCancel(true)
            .setOngoing(false)
            .setContentIntent(contentPendingIntent)
            .addAction(
                R.drawable.ic_shortcut_unlock,
                "UNLOCK PC",
                unlockPendingIntent,
            )
            .addAction(
                android.R.drawable.ic_menu_close_clear_cancel,
                "DISMISS",
                dismissPendingIntent,
            )
            .setDeleteIntent(dismissPendingIntent)
            .build()

        try {
            NotificationManagerCompat.from(context).notify(UNLOCK_NOTIFICATION_ID, notification)
        } catch (_: SecurityException) {
            android.util.Log.w("UnlockPromptNotifier", "Cannot post notification: POST_NOTIFICATIONS permission missing")
        }
    }

    /**
     * Instantly removes any active unlock prompt notification and power event notification when the TLS session drops
     * or when an unlock/dismiss action completes.
     */
    fun cancelUnlockPrompt(context: Context) {
        val nm = NotificationManagerCompat.from(context)
        nm.cancel(UNLOCK_NOTIFICATION_ID)
        nm.cancel(PowerEventActionReceiver.POWER_EVENT_NOTIFICATION_ID)
    }
}
