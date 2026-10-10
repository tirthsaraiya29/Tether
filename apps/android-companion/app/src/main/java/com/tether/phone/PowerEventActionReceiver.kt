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
        const val EXTRA_ACTION = "extra_action"
    }

    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        val eventType = intent.getStringExtra(EXTRA_POWER_EVENT_TYPE) ?: "LOCK"
        val timestamp = intent.getLongExtra(EXTRA_POWER_EVENT_TIMESTAMP, 0L)

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
                    putExtra(EXTRA_ACTION, "ACCEPT")
                }
                context.startActivity(activityIntent)
                NotificationManagerCompat.from(context).cancel(POWER_EVENT_NOTIFICATION_ID)
            }
            ACTION_REJECT -> {
                NotificationManagerCompat.from(context).cancel(POWER_EVENT_NOTIFICATION_ID)
            }
        }
    }
}