package com.tether.phone

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

class TetherServiceReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action
        if ((action == ACTION_HEALTH_CHECK) || 
            (action == Intent.ACTION_BOOT_COMPLETED) || 
            (action == Intent.ACTION_LOCKED_BOOT_COMPLETED)) {
            
            Log.i("TetherReceiver", "Critical trigger received ($action) - Pinging service")
            val serviceIntent = Intent(context, BleGattServerService::class.java).apply {
                this.action = "ACTION_GET_STATUS"
            }
            try {
                context.startForegroundService(serviceIntent)
            } catch (e: Exception) {
                Log.e("TetherReceiver", "Failed to start service from receiver: ${e.message}")
            }
        }
    }

    companion object {
        const val ACTION_HEALTH_CHECK = "com.tether.phone.ALARM_HEALTH_CHECK"
    }
}
