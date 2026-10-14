package com.tether.phone

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.core.content.ContextCompat

class TetherServiceReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val prefs = context.getSharedPreferences("tether_secure_prefs", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("has_unlocked_app_once", false)) {
            Log.i("TetherReceiver", "App not unlocked by user yet; ignoring receiver action: ${intent.action}")
            return
        }

        val action = intent.action
        if ((action == ACTION_HEALTH_CHECK) || 
            (action == Intent.ACTION_BOOT_COMPLETED) || 
            (action == Intent.ACTION_LOCKED_BOOT_COMPLETED) ||
            (action == Intent.ACTION_MY_PACKAGE_REPLACED) ||
            (action == "android.intent.action.QUICKBOOT_POWERON") ||
            (action == "com.htc.intent.action.QUICKBOOT_POWERON")) {
            
            Log.i("TetherReceiver", "Startup boot trigger received ($action) - Starting TetherLanService")
            val serviceIntent = Intent(context, TetherLanService::class.java).apply {
                this.action = "ACTION_GET_STATUS"
            }
            try {
                ContextCompat.startForegroundService(context, serviceIntent)
            } catch (e: Exception) {
                Log.e("TetherReceiver", "Failed to start service from receiver on startup: ${e.message}")
            }
        }
    }

    companion object {
        const val ACTION_HEALTH_CHECK = "com.tether.phone.ALARM_HEALTH_CHECK"
    }
}