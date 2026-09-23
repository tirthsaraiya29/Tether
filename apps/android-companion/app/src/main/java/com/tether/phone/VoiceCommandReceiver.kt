package com.tether.phone

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

class VoiceCommandReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action == "com.tether.phone.ACTION_VOICE_COMMAND") {
            val command = intent.getStringExtra("command_type") ?: intent.getStringExtra("action_command") ?: return
            Log.i("VoiceCommandReceiver", "Received voice command: $command")
            val bleIntent = Intent(context, BleGattServerService::class.java).apply {
                action = command
            }
            try {
                context.startForegroundService(bleIntent)
            } catch (e: Exception) {
                Log.e("VoiceCommandReceiver", "Failed to start BLE service from voice command", e)
            }
        }
    }
}
