package com.tether.phone

import android.content.Intent
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log

class TetherNotificationListenerService : NotificationListenerService() {

    companion object {
        private const val TAG = "TetherNotifListener"
        const val ACTION_NOTIFICATION_POSTED = "com.tether.phone.NOTIFICATION_POSTED"
        const val ACTION_DISMISS_NOTIFICATION = "com.tether.phone.DISMISS_NOTIFICATION"
        const val EXTRA_NOTIF_ID = "extra_notif_id"
        const val EXTRA_NOTIF_PKG = "extra_notif_pkg"
        const val EXTRA_NOTIF_TITLE = "extra_notif_title"
        const val EXTRA_NOTIF_TEXT = "extra_notif_text"
        const val EXTRA_NOTIF_TIME = "extra_notif_time"

        var instance: TetherNotificationListenerService? = null
            private set
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
    }

    override fun onDestroy() {
        if (instance == this) instance = null
        super.onDestroy()
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        if (sbn == null) return

        // Skip ongoing persistent notifications (like Tether foreground service)
        if (sbn.isOngoing || sbn.packageName == packageName) return

        val extras = sbn.notification.extras
        val title = extras.getCharSequence("android.title")?.toString() ?: ""
        val text = extras.getCharSequence("android.text")?.toString() ?: ""

        if (title.isBlank() && text.isBlank()) return

        val intent = Intent(ACTION_NOTIFICATION_POSTED).apply {
            putExtra(EXTRA_NOTIF_ID, sbn.id.toLong())
            putExtra(EXTRA_NOTIF_PKG, sbn.packageName)
            putExtra(EXTRA_NOTIF_TITLE, title)
            putExtra(EXTRA_NOTIF_TEXT, text)
            putExtra(EXTRA_NOTIF_TIME, sbn.postTime)
            setPackage(packageName)
        }
        sendBroadcast(intent)
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification?) {
    }

    fun dismissNotificationByKey(key: String) {
        try {
            cancelNotification(key)
        } catch (e: Exception) {
            Log.w(TAG, "Failed cancelling notification: ${e.message}")
        }
    }
}
