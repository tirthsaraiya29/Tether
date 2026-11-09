package com.tether.phone

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.time.Duration.Companion.milliseconds

class UnlockActionReceiver : BroadcastReceiver() {

    companion object {
        const val TAG = "UnlockActionReceiver"
        const val ACTION_UNLOCK = "com.tether.phone.ACTION_UNLOCK"
        const val ACTION_DISMISS = "com.tether.phone.ACTION_DISMISS"
        const val EXTRA_PEER_NAME = "extra_peer_name"

        private val receiverScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    }

    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        Log.i(TAG, "Received notification action: $action")

        when (action) {
            ACTION_UNLOCK -> {
                // Instantly dismiss notification UI to provide snappy feedback
                UnlockPromptNotifier.cancelUnlockPrompt(context)

                // Require local biometric authentication challenge before dispatching unlock
                val activityIntent = Intent(context, PowerEventActivity::class.java).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
                    putExtra(PowerEventActivity.EXTRA_POWER_EVENT_TYPE, "UNLOCK")
                    putExtra(PowerEventActivity.EXTRA_POWER_EVENT_TIMESTAMP, System.currentTimeMillis())
                }
                context.startActivity(activityIntent)
            }
            ACTION_DISMISS -> {
                UnlockPromptNotifier.cancelUnlockPrompt(context)
            }
        }
    }
}
