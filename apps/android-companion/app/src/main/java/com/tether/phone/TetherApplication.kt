package com.tether.phone

import android.app.Application
import android.util.Log
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.ProcessLifecycleOwner
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class TetherApplication : Application() {

    companion object {
        lateinit var instance: TetherApplication
            private set
    }

    override fun onCreate() {
        super.onCreate()
        instance = this

        // Initialize all notification channels idempotently
        TetherNotificationChannels.createAllChannels(this)

        // AndroidKeyStore warm-up: overlap EC key pair generation with activity startup
        CoroutineScope(Dispatchers.IO).launch {
            try {
                ProductionSecurityEngine().getPublicKeyBytes()
                Log.d("TetherApplication", "AndroidKeyStore warm-up complete")
            } catch (e: Exception) {
                Log.w("TetherApplication", "AndroidKeyStore warm-up failed: ${e.message}")
            }
        }

        // Observe process lifecycle for logging foreground entry
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_START) {
                Log.d("TetherApplication", "App entered foreground")
            }
        }

        ProcessLifecycleOwner.get().lifecycle.addObserver(observer)
    }
}
