package com.tether.phone

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.core.app.NotificationManagerCompat

class UpdateSnoozeReceiver : BroadcastReceiver() {

    companion object {
        const val ACTION_SNOOZE_EXPIRED = "com.tether.phone.ACTION_UPDATE_SNOOZE_EXPIRED"
        const val ACTION_SNOOZE_NOW = "com.tether.phone.ACTION_UPDATE_SNOOZE_NOW"
        const val EXTRA_VERSION = "extra_version"
        const val EXTRA_HOURS = "extra_hours"
        private const val TAG = "UpdateSnoozeReceiver"
    }

    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        Log.i(TAG, "Received snooze action: $action")

        when (action) {
            ACTION_SNOOZE_NOW -> {
                val version = intent.getStringExtra(EXTRA_VERSION) ?: ""
                val hours = intent.getIntExtra(EXTRA_HOURS, 4)
                if (version.isNotBlank()) {
                    UpdateChecker.snooze(context, version, hours)
                }
                // Dismiss the notification
                NotificationManagerCompat.from(context).cancel(UpdateCheckService.NOTIFICATION_ID)
            }
            ACTION_SNOOZE_EXPIRED -> {
                val version = intent.getStringExtra(EXTRA_VERSION) ?: ""
                // Start UpdateCheckService to fetch and post the high priority notification
                val serviceIntent = Intent(context, UpdateCheckService::class.java).apply {
                    putExtra(EXTRA_VERSION, version)
                }
                context.startForegroundService(serviceIntent)
            }
        }
    }
}
