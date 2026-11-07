package com.tether.phone

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.edit

class PowerEventActionReceiver : BroadcastReceiver() {

    companion object {
        const val POWER_EVENT_NOTIFICATION_ID = 4001
        const val ACTION_ACCEPT = "com.tether.phone.POWER_EVENT_ACCEPT"
        const val ACTION_REJECT = "com.tether.phone.POWER_EVENT_REJECT"
        const val EXTRA_POWER_EVENT_TYPE = "eventType"
        const val EXTRA_POWER_EVENT_TIMESTAMP = "eventTimestamp"
        const val EXTRA_LOCK_SESSION_ID = "lockSessionId"
        const val EXTRA_ACTION = "extra_action"
    }

    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        val eventType = intent.getStringExtra(EXTRA_POWER_EVENT_TYPE) ?: "LOCK"
        val timestamp = intent.getLongExtra(EXTRA_POWER_EVENT_TIMESTAMP, 0L)
        val lockSessionId = intent.getStringExtra(EXTRA_LOCK_SESSION_ID)

        val prefs = context.getSharedPreferences("tether_secure_prefs", Context.MODE_PRIVATE)
        prefs.edit {
            putString("last_answered_power_event_type", eventType)
            putLong("last_answered_power_event_timestamp_ms", timestamp)
        }

        when (action) {
            ACTION_ACCEPT -> {
                val activityIntent = Intent(context, PowerEventActivity::class.java).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
                    putExtra(EXTRA_POWER_EVENT_TYPE, eventType)
                    putExtra(EXTRA_POWER_EVENT_TIMESTAMP, timestamp)
                    putExtra(EXTRA_LOCK_SESSION_ID, lockSessionId)
                    putExtra(EXTRA_ACTION, "ACCEPT")
                }
                context.startActivity(activityIntent)
                val nm = NotificationManagerCompat.from(context)
                nm.cancel(POWER_EVENT_NOTIFICATION_ID)
                nm.cancel(UnlockPromptNotifier.UNLOCK_NOTIFICATION_ID)
            }
            ACTION_REJECT -> {
                prefs.edit {
                    remove("is_unlock_prompt_dismissed")
                }
                val dismissIntent = Intent(context, TetherLanService::class.java).apply {
                    this.action = TetherLanService.ACTION_DISMISS_LOCK_SESSION
                    putExtra(TetherLanService.EXTRA_LOCK_SESSION_ID, lockSessionId)
                }
                context.startService(dismissIntent)
                val nm = NotificationManagerCompat.from(context)
                nm.cancel(POWER_EVENT_NOTIFICATION_ID)
                nm.cancel(UnlockPromptNotifier.UNLOCK_NOTIFICATION_ID)
            }
        }
    }
}
