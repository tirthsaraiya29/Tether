package com.tether.phone

import android.content.Context
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class UpdateViewModel : ViewModel() {

    private val _updateInfo = MutableStateFlow<UpdateInfo?>(null)
    val updateInfo: StateFlow<UpdateInfo?> = _updateInfo.asStateFlow()

    private val _dialogVisible = MutableStateFlow(false)
    val dialogVisible: StateFlow<Boolean> = _dialogVisible.asStateFlow()

    private var lastCheckTimestamp = 0L

    fun onAppBackgrounded() {
        lastCheckTimestamp = 0L
    }

    /**
     * Call this on every app launch and every foreground entry.
     * [currentVersion] should come from BuildConfig.VERSION_NAME.
     */
    fun checkForUpdate(currentVersion: String, context: Context? = null) {
        val now = System.currentTimeMillis()
        // 1-second guard against rapid duplicate triggers during config changes
        if (now - lastCheckTimestamp < 1_000L) return
        lastCheckTimestamp = now

        // First check cached update info for instant popup on launch
        if (context != null) {
            val cached = UpdateChecker.getCachedUpdateInfo(context)
            if (cached != null && UpdateChecker.isNewerVersion(local = currentVersion, remote = cached.latestVersion)) {
                _updateInfo.value = cached
                _dialogVisible.value = true
            }
        }

        viewModelScope.launch {
            val latest = UpdateChecker.fetchLatestRelease() ?: return@launch
            if (context != null) {
                UpdateChecker.cacheUpdateInfo(context, latest)
            }
            if (UpdateChecker.isNewerVersion(local = currentVersion, remote = latest.latestVersion)) {
                Log.i("UpdateViewModel", "New version available: ${latest.latestVersion}")
                _updateInfo.value = latest
                if (!_dialogVisible.value) {
                    _dialogVisible.value = true
                }
            }
        }
    }

    fun dismissDialog() {
        _dialogVisible.value = false
    }
}
