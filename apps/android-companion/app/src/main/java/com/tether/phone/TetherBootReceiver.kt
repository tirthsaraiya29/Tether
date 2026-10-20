package com.tether.phone

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.core.content.ContextCompat

class TetherBootReceiver : BroadcastReceiver() {
    companion object {
        private const val TAG = "TetherBootReceiver"
    }

    override fun onReceive(context: Context, intent: Intent) {
        val prefs = context.getSharedPreferences("tether_secure_prefs", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("has_unlocked_app_once", false)) {
            Log.i(TAG, "App not unlocked by user yet; ignoring boot action: ${intent.action}")
            return
        }

        val action = intent.action ?: return
        Log.i(TAG, "Boot intent received: $action")

        when (action) {
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_LOCKED_BOOT_COMPLETED,
            Intent.ACTION_MY_PACKAGE_REPLACED,
            "android.intent.action.QUICKBOOT_POWERON",
            "com.htc.intent.action.QUICKBOOT_POWERON" -> {
                val serviceIntent = Intent(context, TetherLanService::class.java).apply {
                    this.action = "ACTION_GET_STATUS"
                }
                try {
                    ContextCompat.startForegroundService(context, serviceIntent)
                    UpdateCheckService.startCheck(context)
                } catch (e: Exception) {
                    Log.e(TAG, "Failed starting TetherLanService on boot: ${e.message}")
                }
            }
        }
    }
}
