package com.tether.phone

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.core.content.ContextCompat

class TetherAlarmReceiver : BroadcastReceiver() {
    companion object {
        private const val TAG = "TetherAlarmReceiver"
        const val ACTION_HEALTH_CHECK = "com.tether.phone.ALARM_HEALTH_CHECK"
    }

    override fun onReceive(context: Context, intent: Intent) {
        val prefs = context.getSharedPreferences("tether_secure_prefs", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("has_unlocked_app_once", false)) {
            Log.i(TAG, "App not unlocked by user yet; ignoring alarm action: ${intent.action}")
            return
        }

        if (intent.action == ACTION_HEALTH_CHECK) {
            Log.i(TAG, "Internal health check alarm received - verifying TetherLanService state")
            val serviceIntent = Intent(context, TetherLanService::class.java).apply {
                action = "ACTION_GET_STATUS"
            }
            try {
                ContextCompat.startForegroundService(context, serviceIntent)
            } catch (e: Exception) {
                Log.e(TAG, "Failed starting TetherLanService from alarm receiver: ${e.message}")
            }
        }
    }
}
