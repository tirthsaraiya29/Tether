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
     * Call this on every app launch and foreground entry.
     * [currentVersion] should come from BuildConfig.VERSION_NAME.
     */
    fun checkForUpdate(currentVersion: String, context: Context) {
        if (UpdateChecker.isDebugMode(context)) {
            Log.d("UpdateViewModel", "Debug mode active - update checking bypassed.")
            return
        }

        val now = System.currentTimeMillis()
        if (now - lastCheckTimestamp < 5_000L) return
        lastCheckTimestamp = now

        // Check cached update info first for immediate UI if newer and not snoozed
        val cached = UpdateChecker.getCachedUpdateInfo(context)
        if (cached != null && UpdateChecker.isNewerVersion(local = currentVersion, remote = cached.latestVersion)) {
            if (!UpdateChecker.isSnoozed(context, cached.latestVersion)) {
                _updateInfo.value = cached
                _dialogVisible.value = true
            }
        }

        viewModelScope.launch {
            val latest = UpdateChecker.fetchLatestRelease(context) ?: return@launch
            if (UpdateChecker.isNewerVersion(local = currentVersion, remote = latest.latestVersion)) {
                if (!UpdateChecker.isSnoozed(context, latest.latestVersion)) {
                    Log.i("UpdateViewModel", "New version available: ${latest.latestVersion}")
                    _updateInfo.value = latest
                    _dialogVisible.value = true
                }
            }
        }
    }

    fun snooze(context: Context, hours: Int) {
        val version = _updateInfo.value?.latestVersion ?: ""
        if (version.isNotBlank()) {
            UpdateChecker.snooze(context, version, hours)
        }
        _dialogVisible.value = false
    }

    fun dismissDialog() {
        _dialogVisible.value = false
    }
}
