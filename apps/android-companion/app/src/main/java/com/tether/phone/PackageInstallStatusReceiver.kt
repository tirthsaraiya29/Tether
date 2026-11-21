package com.tether.phone

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.os.Build
import android.util.Log
import java.io.File

class PackageInstallStatusReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "PackageInstallStatus"
    }

    override fun onReceive(context: Context, intent: Intent) {
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
        when (status) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                val confirmIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra(Intent.EXTRA_INTENT)
                }
                if (confirmIntent != null) {
                    confirmIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    context.startActivity(confirmIntent)
                } else {
                    Log.e(TAG, "EXTRA_INTENT missing in STATUS_PENDING_USER_ACTION broadcast")
                }
            }
            PackageInstaller.STATUS_SUCCESS -> {
                Log.i(TAG, "Package installed successfully")
                try {
                    File(context.cacheDir, "updates").deleteRecursively()
                } catch (_: Exception) {}
            }
            else -> {
                val msg = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE)
                Log.w(TAG, "Package install finished with status=$status: $msg")
            }
        }
    }
}
