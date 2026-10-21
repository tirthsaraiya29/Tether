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
                // Use goAsync() to keep the receiver process alive while dispatching
                // the network payload over TLS 1.3 asynchronously.
                val pendingResult = goAsync()
                receiverScope.launch {
                    try {
                        val service = TetherLanService.instance
                        if (service != null) {
                            withTimeoutOrNull(5000.milliseconds) {
                                service.sendCommand("unlock")
                            }
                            Log.i(TAG, "Unlock command dispatched over active TLS session.")
                        } else {
                            Log.w(TAG, "TetherLanService instance is null; cannot send unlock command.")
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed sending unlock command from notification action: ${e.message}", e)
                    } finally {
                        pendingResult.finish()
                    }
                }
            }
            ACTION_DISMISS -> {
                UnlockPromptNotifier.cancelUnlockPrompt(context)
            }
        }
    }
}
