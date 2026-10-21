package com.tether.phone
import android.content.Context
import androidx.core.app.NotificationManagerCompat
object UnlockPromptNotifier {
    const val UNLOCK_NOTIFICATION_ID = 2001
    /**
     * Suppresses persistent TLS session / unlock notifications per user requirement.
     * Always cancels any existing unlock notification ID.
     */
    @Suppress("UNUSED_PARAMETER")
    fun showUnlockPrompt(context: Context, peerDeviceName: String) {
        cancelUnlockPrompt(context)
    }
    /**
     * Instantly removes any active unlock prompt notification and power event notification when the TLS session drops
     * or when an unlock/dismiss action completes.
     */
    fun cancelUnlockPrompt(context: Context) {
        val nm = NotificationManagerCompat.from(context)
        nm.cancel(UNLOCK_NOTIFICATION_ID)
        nm.cancel(PowerEventActionReceiver.POWER_EVENT_NOTIFICATION_ID)
    }
}
