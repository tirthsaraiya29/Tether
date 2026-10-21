package com.tether.phone
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
class UpdateCheckService : Service() {
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        TetherNotificationChannels.createAllChannels(applicationContext)
        // Mandatory immediate startForeground to satisfy FGS requirements
        try {
            val foregroundNotification = NotificationCompat.Builder(applicationContext, TetherNotificationChannels.CHANNEL_UPDATES)
                .setSmallIcon(R.drawable.ic_launcher_foreground)
                .setContentTitle("Checking for Tether updates")
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .setSilent(true)
                .build()
            startForeground(SERVICE_FOREGROUND_ID, foregroundNotification)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to startForeground for UpdateCheckService: ${e.message}")
        }
        serviceScope.launch {
            try {
                checkAndNotifyUpdate()
            } catch (e: Exception) {
                Log.e(TAG, "Error in UpdateCheckService: ${e.message}", e)
            } finally {
                try {
                    stopForeground(STOP_FOREGROUND_REMOVE)
                } catch (_: Exception) {}
                stopSelf(startId)
            }
        }
        return START_NOT_STICKY
    }
    private suspend fun checkAndNotifyUpdate() {
        val latest = UpdateChecker.fetchLatestRelease() ?: return
        val currentVersion = BuildConfig.VERSION_NAME
        if (UpdateChecker.isNewerVersion(local = currentVersion, remote = latest.latestVersion)) {
            Log.i(TAG, "New update found in background: ${latest.latestVersion}")
            UpdateChecker.cacheUpdateInfo(applicationContext, latest)
            notifyUpdateAvailable(latest)
        }
    }
    private fun notifyUpdateAvailable(updateInfo: UpdateInfo) {
        val intent = Intent(applicationContext, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
            putExtra(EXTRA_FROM_UPDATE_NOTIFICATION, true)
        }
        val pendingIntent = PendingIntent.getActivity(
            applicationContext,
            NOTIFICATION_REQ_CODE,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = NotificationCompat.Builder(applicationContext, TetherNotificationChannels.CHANNEL_UPDATES)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentTitle("Tether Update Available")
            .setContentText("Version v${updateInfo.latestVersion} is ready for download.")
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()
        val hasPermission = Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
                ActivityCompat.checkSelfPermission(this, android.Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
        if (hasPermission) {
            NotificationManagerCompat.from(applicationContext).notify(NOTIFICATION_ID, notification)
        } else {
            Log.w(TAG, "POST_NOTIFICATIONS permission not granted; background notification skipped")
        }
    }
    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
    }
    companion object {
        private const val TAG = "UpdateCheckService"
        private const val SERVICE_FOREGROUND_ID = 5000
        // NOTIFICATION_ID = 5001 and NOTIFICATION_REQ_CODE = 5002 to avoid collision with UnlockPromptNotifier (2001)
        const val NOTIFICATION_ID = 5001
        private const val NOTIFICATION_REQ_CODE = 5002
        const val EXTRA_FROM_UPDATE_NOTIFICATION = "extra_from_update_notification"
        fun startCheck(context: Context) {
            try {
                val intent = Intent(context, UpdateCheckService::class.java)
                ContextCompat.startForegroundService(context, intent)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start UpdateCheckService: ${e.message}")
            }
        }
    }
}
