package com.tether.phone

import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.Locale

data class FileTransferUiState(
    val isTransferring: Boolean = false,
    val fileName: String = "",
    val isUpload: Boolean = false,
    val bytesTransferred: Long = 0L,
    val totalBytes: Long = 0L,
    val speedBps: Long = 0L,
    val etaSec: Long = 0L,
    val savedPath: String? = null,
    val error: String? = null
)

object FileTransferNotificationManager {
    private const val NOTIFICATION_ID_BASE = 9100

    private val _transferState = MutableStateFlow(FileTransferUiState())
    val transferState = _transferState.asStateFlow()

    fun showProgress(
        context: Context,
        transferId: Int,
        fileName: String,
        isUpload: Boolean,
        bytesTransferred: Long,
        totalBytes: Long,
        speedBps: Long,
        etaSec: Long
    ) {
        val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        TetherNotificationChannels.createAllChannels(context)

        val percent = if (totalBytes > 0) ((bytesTransferred * 100) / totalBytes).toInt().coerceIn(0, 100) else 0
        val speedStr = formatSpeed(speedBps)
        val etaStr = formatEta(etaSec)
        val sizeStr = if (totalBytes > 0) "${formatBytes(bytesTransferred)} / ${formatBytes(totalBytes)}" else formatBytes(bytesTransferred)

        _transferState.value = FileTransferUiState(
            isTransferring = true,
            fileName = fileName,
            isUpload = isUpload,
            bytesTransferred = bytesTransferred,
            totalBytes = totalBytes,
            speedBps = speedBps,
            etaSec = etaSec,
            savedPath = null,
            error = null
        )

        val actionTitle = if (isUpload) "Uploading $fileName" else "Downloading $fileName"
        val statusText = "$percent% ($sizeStr) • $speedStr • $etaStr"

        val notification = NotificationCompat.Builder(context, TetherNotificationChannels.CHANNEL_FILE_TRANSFER)
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setContentTitle(actionTitle)
            .setContentText(statusText)
            .setProgress(100, percent, totalBytes <= 0)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_PROGRESS)
            .build()

        notificationManager.notify(NOTIFICATION_ID_BASE + (transferId % 100), notification)
    }

    fun showComplete(
        context: Context,
        transferId: Int,
        fileName: String,
        isUpload: Boolean,
        savedUri: Uri?,
        savedPath: String?
    ) {
        val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        TetherNotificationChannels.createAllChannels(context)

        _transferState.value = FileTransferUiState(
            isTransferring = false,
            fileName = fileName,
            isUpload = isUpload,
            bytesTransferred = 0L,
            totalBytes = 0L,
            speedBps = 0L,
            etaSec = 0L,
            savedPath = savedPath ?: fileName,
            error = null
        )

        val title = if (isUpload) "Upload Complete" else "Download Complete"
        val body = if (isUpload) {
            "Sent $fileName to PC"
        } else {
            "Saved to: ${savedPath ?: fileName}"
        }

        val builder = NotificationCompat.Builder(context, TetherNotificationChannels.CHANNEL_FILE_TRANSFER)
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setContentTitle(title)
            .setContentText(body)
            .setProgress(0, 0, false)
            .setOngoing(false)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)

        if (savedUri != null) {
            try {
                val openIntent = Intent(Intent.ACTION_VIEW).apply {
                    setDataAndType(savedUri, context.contentResolver.getType(savedUri) ?: "*/*")
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                val pendingIntent = PendingIntent.getActivity(
                    context,
                    NOTIFICATION_ID_BASE + (transferId % 100),
                    openIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )
                builder.setContentIntent(pendingIntent)
            } catch (_: Exception) {}
        }

        notificationManager.notify(NOTIFICATION_ID_BASE + (transferId % 100), builder.build())
    }

    fun showError(
        context: Context,
        transferId: Int,
        fileName: String,
        isUpload: Boolean,
        error: String
    ) {
        val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        TetherNotificationChannels.createAllChannels(context)

        _transferState.value = FileTransferUiState(
            isTransferring = false,
            fileName = fileName,
            isUpload = isUpload,
            bytesTransferred = 0L,
            totalBytes = 0L,
            speedBps = 0L,
            etaSec = 0L,
            savedPath = null,
            error = error
        )

        val title = if (isUpload) "Upload Failed" else "Download Failed"
        val notification = NotificationCompat.Builder(context, TetherNotificationChannels.CHANNEL_FILE_TRANSFER)
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setContentTitle(title)
            .setContentText("$fileName: $error")
            .setProgress(0, 0, false)
            .setOngoing(false)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .build()

        notificationManager.notify(NOTIFICATION_ID_BASE + (transferId % 100), notification)
    }

    fun clearState() {
        _transferState.value = FileTransferUiState()
    }

    fun formatSpeed(bps: Long): String {
        return when {
            bps <= 0 -> "0 KB/s"
            bps < 1024 * 1024 -> String.format(Locale.US, "%d KB/s", bps / 1024)
            else -> String.format(Locale.US, "%.1f MB/s", bps / (1024.0 * 1024.0))
        }
    }

    fun formatEta(sec: Long): String {
        return when {
            sec <= 0 -> "ETA: 0s"
            sec < 60 -> "ETA: ${sec}s"
            sec < 3600 -> "ETA: ${sec / 60}m ${sec % 60}s"
            else -> "ETA: ${sec / 3600}h ${(sec % 3600) / 60}m"
        }
    }

    fun formatBytes(bytes: Long): String {
        return when {
            bytes < 0 -> "0 B"
            bytes < 1024 -> "$bytes B"
            bytes < 1024 * 1024 -> String.format(Locale.US, "%.1f KB", bytes / 1024.0)
            bytes < 1024 * 1024 * 1024 -> String.format(Locale.US, "%.1f MB", bytes / (1024.0 * 1024.0))
            else -> String.format(Locale.US, "%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0))
        }
    }
}
