package com.tether.phone

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import org.json.JSONArray
import org.json.JSONObject

object LaptopStateCache {
    private const val PREFS_NAME = "tether_laptop_cache"
    private const val KEY_LAPTOP_TELEMETRY = "cache_laptop_telemetry"
    private const val KEY_ADMIN_TELEMETRY = "cache_admin_telemetry"
    private const val KEY_BATTERY_HEALTH = "cache_battery_health"
    private const val KEY_BATTERY_REPORT = "cache_battery_report"
    private const val KEY_HARDWARE_SPECS = "cache_hardware_specs"
    private const val KEY_POWER_PLANS = "cache_power_plans"
    private const val KEY_SERVICES = "cache_services"
    private const val KEY_UPDATES = "cache_updates"
    private const val KEY_AUDIO_DEVICES = "cache_audio_devices"
    private const val KEY_AUDIO_SESSIONS = "cache_audio_sessions"
    private const val KEY_WINDOWS = "cache_windows"
    private const val KEY_APPS = "cache_apps"
    private const val KEY_VOLUME = "cache_volume"
    private const val KEY_BRIGHTNESS = "cache_brightness"
    private const val KEY_LAST_SYNC_MS = "cache_last_sync_ms"

    private fun prefs(context: Context): SharedPreferences {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    fun saveMetrics(context: Context, volume: Int, brightness: Int) {
        prefs(context).edit {
            if (volume >= 0) putInt(KEY_VOLUME, volume)
            if (brightness >= 0) putInt(KEY_BRIGHTNESS, brightness)
            putLong(KEY_LAST_SYNC_MS, System.currentTimeMillis())
        }
    }

    fun getMetrics(context: Context): Pair<Int, Int>? {
        val p = prefs(context)
        val vol = p.getInt(KEY_VOLUME, -1)
        val bright = p.getInt(KEY_BRIGHTNESS, -1)
        if (vol < 0 && bright < 0) return null
        return Pair(vol.coerceAtLeast(0), bright.coerceAtLeast(0))
    }

    fun saveLaptopTelemetry(context: Context, t: LaptopTelemetry) {
        val json = JSONObject().apply {
            put("powerState", t.powerState.name)
            put("batteryPercent", t.batteryPercent)
            put("isCharging", t.isCharging)
            put("wallpaperPath", t.wallpaperPath ?: "")
            put("lastSeenAtMs", t.lastSeenAtMs)
        }
        prefs(context).edit {
            putString(KEY_LAPTOP_TELEMETRY, json.toString())
            putLong(KEY_LAST_SYNC_MS, System.currentTimeMillis())
        }
    }

    fun getLaptopTelemetry(context: Context): LaptopTelemetry? {
        val raw = prefs(context).getString(KEY_LAPTOP_TELEMETRY, null) ?: return null
        return try {
            val j = JSONObject(raw)
            val pState = try {
                LaptopPowerState.valueOf(j.optString("powerState", LaptopPowerState.UNKNOWN.name))
            } catch (_: Exception) {
                LaptopPowerState.UNKNOWN
            }
            LaptopTelemetry(
                powerState = pState,
                batteryPercent = j.optInt("batteryPercent", -1),
                isCharging = j.optBoolean("isCharging", false),
                wallpaperPath = j.optString("wallpaperPath", "").ifEmpty { null },
                lastSeenAtMs = j.optLong("lastSeenAtMs", 0L)
            )
        } catch (_: Exception) {
            null
        }
    }

    fun saveAdminTelemetry(context: Context, t: AdminTelemetry) {
        val json = JSONObject().apply {
            put("cpuUsage", t.cpuUsage)
            put("totalRamMb", t.totalRamMb)
            put("availRamMb", t.availRamMb)
            put("ramUsagePct", t.ramUsagePct)
            put("gpuName", t.gpuName)
            put("gpuVramMb", t.gpuVramMb)
            put("cpuCores", t.cpuCores)
            put("uptimeSeconds", t.uptimeSeconds)

            val dArr = JSONArray()
            t.disks.forEach { d ->
                dArr.put(JSONObject().apply {
                    put("name", d.name)
                    put("volumeLabel", d.volumeLabel)
                    put("totalGb", d.totalGb)
                    put("freeGb", d.freeGb)
                    put("format", d.format)
                })
            }
            put("disks", dArr)

            val nArr = JSONArray()
            t.networks.forEach { n ->
                nArr.put(JSONObject().apply {
                    put("name", n.name)
                    put("description", n.description)
                    put("type", n.type)
                    put("bytesReceived", n.bytesReceived)
                    put("bytesSent", n.bytesSent)
                    put("speedMbps", n.speedMbps)
                })
            }
            put("networks", nArr)
        }
        prefs(context).edit {
            putString(KEY_ADMIN_TELEMETRY, json.toString())
            putLong(KEY_LAST_SYNC_MS, System.currentTimeMillis())
        }
    }

    fun getAdminTelemetry(context: Context): AdminTelemetry? {
        val raw = prefs(context).getString(KEY_ADMIN_TELEMETRY, null) ?: return null
        return try {
            val j = JSONObject(raw)
            val dList = mutableListOf<DiskUsageItem>()
            val dArr = j.optJSONArray("disks")
            if (dArr != null) {
                for (i in 0 until dArr.length()) {
                    val d = dArr.getJSONObject(i)
                    dList.add(DiskUsageItem(
                        name = d.optString("name", "C:"),
                        volumeLabel = d.optString("volumeLabel", ""),
                        totalGb = d.optDouble("totalGb", 0.0),
                        freeGb = d.optDouble("freeGb", 0.0),
                        format = d.optString("format", "NTFS")
                    ))
                }
            }

            val nList = mutableListOf<NetworkAdapterItem>()
            val nArr = j.optJSONArray("networks")
            if (nArr != null) {
                for (i in 0 until nArr.length()) {
                    val n = nArr.getJSONObject(i)
                    nList.add(NetworkAdapterItem(
                        name = n.optString("name", "Ethernet"),
                        description = n.optString("description", ""),
                        type = n.optString("type", ""),
                        bytesReceived = n.optLong("bytesReceived", 0L),
                        bytesSent = n.optLong("bytesSent", 0L),
                        speedMbps = n.optLong("speedMbps", 0L)
                    ))
                }
            }

            AdminTelemetry(
                cpuUsage = j.optInt("cpuUsage", 0),
                totalRamMb = j.optLong("totalRamMb", 0L),
                availRamMb = j.optLong("availRamMb", 0L),
                ramUsagePct = j.optInt("ramUsagePct", 0),
                disks = dList,
                networks = nList,
                gpuName = j.optString("gpuName", ""),
                gpuVramMb = j.optLong("gpuVramMb", 0L),
                cpuCores = j.optInt("cpuCores", 0),
                uptimeSeconds = j.optLong("uptimeSeconds", 0L)
            )
        } catch (_: Exception) {
            null
        }
    }

    fun saveBatteryHealth(context: Context, h: BatteryHealthState) {
        val json = JSONObject().apply {
            put("designCapacityMwh", h.designCapacityMwh)
            put("fullChargeCapacityMwh", h.fullChargeCapacityMwh)
            put("wearLevelPct", h.wearLevelPct)
            put("cycleCount", h.cycleCount)
        }
        prefs(context).edit { putString(KEY_BATTERY_HEALTH, json.toString()) }
    }

    fun getBatteryHealth(context: Context): BatteryHealthState? {
        val raw = prefs(context).getString(KEY_BATTERY_HEALTH, null) ?: return null
        return try {
            val j = JSONObject(raw)
            BatteryHealthState(
                designCapacityMwh = j.optDouble("designCapacityMwh", 0.0),
                fullChargeCapacityMwh = j.optDouble("fullChargeCapacityMwh", 0.0),
                wearLevelPct = j.optInt("wearLevelPct", 0),
                cycleCount = j.optInt("cycleCount", 0)
            )
        } catch (_: Exception) {
            null
        }
    }

    fun saveBatteryReport(context: Context, r: BatteryReportDetails) {
        val json = JSONObject().apply {
            put("success", r.success)
            put("batteryName", r.batteryName)
            put("manufacturer", r.manufacturer)
            put("serialNumber", r.serialNumber)
            put("chemistry", r.chemistry)
            put("designCapacityMwh", r.designCapacityMwh)
            put("fullChargeCapacityMwh", r.fullChargeCapacityMwh)
            put("cycleCount", r.cycleCount)
            put("healthPercent", r.healthPercent)
            put("reportTimestamp", r.reportTimestamp)
            put("errorMessage", r.errorMessage)
        }
        prefs(context).edit { putString(KEY_BATTERY_REPORT, json.toString()) }
    }

    fun getBatteryReport(context: Context): BatteryReportDetails? {
        val raw = prefs(context).getString(KEY_BATTERY_REPORT, null) ?: return null
        return try {
            val j = JSONObject(raw)
            BatteryReportDetails(
                success = j.optBoolean("success", false),
                batteryName = j.optString("batteryName", ""),
                manufacturer = j.optString("manufacturer", ""),
                serialNumber = j.optString("serialNumber", ""),
                chemistry = j.optString("chemistry", ""),
                designCapacityMwh = j.optDouble("designCapacityMwh", 0.0),
                fullChargeCapacityMwh = j.optDouble("fullChargeCapacityMwh", 0.0),
                cycleCount = j.optInt("cycleCount", 0),
                healthPercent = j.optInt("healthPercent", 100),
                reportTimestamp = j.optString("reportTimestamp", ""),
                errorMessage = j.optString("errorMessage", "")
            )
        } catch (_: Exception) {
            null
        }
    }

    fun saveHardwareSpecs(context: Context, s: HardwareSpecs) {
        val json = JSONObject().apply {
            put("processorName", s.processorName)
            put("coreCount", s.coreCount)
            put("totalMemoryMb", s.totalMemoryMb)
            put("gpuName", s.gpuName)
            put("gpuVramMb", s.gpuVramMb)
            put("systemManufacturer", s.systemManufacturer)
            put("systemModel", s.systemModel)
            put("biosVersion", s.biosVersion)
            put("osDescription", s.osDescription)
            put("uptimeSeconds", s.uptimeSeconds)
        }
        prefs(context).edit { putString(KEY_HARDWARE_SPECS, json.toString()) }
    }

    fun getHardwareSpecs(context: Context): HardwareSpecs? {
        val raw = prefs(context).getString(KEY_HARDWARE_SPECS, null) ?: return null
        return try {
            val j = JSONObject(raw)
            HardwareSpecs(
                processorName = j.optString("processorName", ""),
                coreCount = j.optInt("coreCount", 0),
                totalMemoryMb = j.optLong("totalMemoryMb", 0L),
                gpuName = j.optString("gpuName", ""),
                gpuVramMb = j.optLong("gpuVramMb", 0L),
                systemManufacturer = j.optString("systemManufacturer", ""),
                systemModel = j.optString("systemModel", ""),
                biosVersion = j.optString("biosVersion", ""),
                osDescription = j.optString("osDescription", ""),
                uptimeSeconds = j.optLong("uptimeSeconds", 0L)
            )
        } catch (_: Exception) {
            null
        }
    }

    fun savePowerPlans(context: Context, plans: List<PowerPlanItem>) {
        val arr = JSONArray()
        plans.forEach { p ->
            arr.put(JSONObject().apply {
                put("guid", p.guid)
                put("name", p.name)
                put("isActive", p.isActive)
            })
        }
        prefs(context).edit { putString(KEY_POWER_PLANS, arr.toString()) }
    }

    fun getPowerPlans(context: Context): List<PowerPlanItem> {
        val raw = prefs(context).getString(KEY_POWER_PLANS, null) ?: return emptyList()
        return try {
            val arr = JSONArray(raw)
            val list = mutableListOf<PowerPlanItem>()
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                list.add(PowerPlanItem(
                    guid = o.optString("guid", ""),
                    name = o.optString("name", "Power Plan"),
                    isActive = o.optBoolean("isActive", false)
                ))
            }
            list
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun saveServices(context: Context, services: List<WindowsServiceItem>) {
        val arr = JSONArray()
        services.take(300).forEach { s ->
            arr.put(JSONObject().apply {
                put("name", s.name)
                put("displayName", s.displayName)
                put("status", s.status)
                put("canStop", s.canStop)
            })
        }
        prefs(context).edit { putString(KEY_SERVICES, arr.toString()) }
    }

    fun getServices(context: Context): List<WindowsServiceItem> {
        val raw = prefs(context).getString(KEY_SERVICES, null) ?: return emptyList()
        return try {
            val arr = JSONArray(raw)
            val list = mutableListOf<WindowsServiceItem>()
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                list.add(WindowsServiceItem(
                    name = o.optString("name", ""),
                    displayName = o.optString("displayName", ""),
                    status = o.optString("status", "Stopped"),
                    canStop = o.optBoolean("canStop", false)
                ))
            }
            list
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun saveUpdates(context: Context, u: WindowsUpdateState) {
        val json = JSONObject().apply {
            put("pendingCount", u.pendingCount)
            put("isAvailable", u.isAvailable)
            val tArr = JSONArray()
            u.titles.forEach { tArr.put(it) }
            put("titles", tArr)
        }
        prefs(context).edit { putString(KEY_UPDATES, json.toString()) }
    }

    fun getUpdates(context: Context): WindowsUpdateState? {
        val raw = prefs(context).getString(KEY_UPDATES, null) ?: return null
        return try {
            val j = JSONObject(raw)
            val tList = mutableListOf<String>()
            val tArr = j.optJSONArray("titles")
            if (tArr != null) {
                for (i in 0 until tArr.length()) {
                    tList.add(tArr.getString(i))
                }
            }
            WindowsUpdateState(
                pendingCount = j.optInt("pendingCount", 0),
                isAvailable = j.optBoolean("isAvailable", false),
                titles = tList
            )
        } catch (_: Exception) {
            null
        }
    }

    fun saveAudioDevices(context: Context, devices: List<AudioDeviceItem>) {
        val arr = JSONArray()
        devices.forEach { d ->
            arr.put(JSONObject().apply {
                put("id", d.id)
                put("name", d.name)
                put("isDefault", d.isDefault)
                put("isInput", d.isInput)
            })
        }
        prefs(context).edit { putString(KEY_AUDIO_DEVICES, arr.toString()) }
    }

    fun getAudioDevices(context: Context): List<AudioDeviceItem> {
        val raw = prefs(context).getString(KEY_AUDIO_DEVICES, null) ?: return emptyList()
        return try {
            val arr = JSONArray(raw)
            val list = mutableListOf<AudioDeviceItem>()
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                list.add(AudioDeviceItem(
                    id = o.optString("id", ""),
                    name = o.optString("name", "Audio Device"),
                    isDefault = o.optBoolean("isDefault", false),
                    isInput = o.optBoolean("isInput", false)
                ))
            }
            list
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun saveAudioSessions(context: Context, sessions: List<AppAudioSessionItem>) {
        val arr = JSONArray()
        sessions.forEach { s ->
            arr.put(JSONObject().apply {
                put("pid", s.pid)
                put("processName", s.processName)
                put("volumePercent", s.volumePercent)
                put("isMuted", s.isMuted)
            })
        }
        prefs(context).edit { putString(KEY_AUDIO_SESSIONS, arr.toString()) }
    }

    fun getAudioSessions(context: Context): List<AppAudioSessionItem> {
        val raw = prefs(context).getString(KEY_AUDIO_SESSIONS, null) ?: return emptyList()
        return try {
            val arr = JSONArray(raw)
            val list = mutableListOf<AppAudioSessionItem>()
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                list.add(AppAudioSessionItem(
                    pid = o.optInt("pid", 0),
                    processName = o.optString("processName", "Application"),
                    volumePercent = o.optInt("volumePercent", 50),
                    isMuted = o.optBoolean("isMuted", false)
                ))
            }
            list
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun saveWindows(context: Context, windows: List<DesktopWindow>) {
        val arr = JSONArray()
        windows.forEach { w ->
            arr.put(JSONObject().apply {
                put("hwnd", w.hwnd)
                put("title", w.title)
                put("processName", w.processName)
                put("processId", w.processId)
                put("width", w.width)
                put("height", w.height)
                put("iconB64", w.iconB64 ?: "")
            })
        }
        prefs(context).edit { putString(KEY_WINDOWS, arr.toString()) }
    }

    fun getWindows(context: Context): List<DesktopWindow> {
        val raw = prefs(context).getString(KEY_WINDOWS, null) ?: return emptyList()
        return try {
            val arr = JSONArray(raw)
            val list = mutableListOf<DesktopWindow>()
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                list.add(DesktopWindow(
                    hwnd = o.optLong("hwnd", 0L),
                    title = o.optString("title", ""),
                    processName = o.optString("processName", ""),
                    processId = o.optInt("processId", 0),
                    width = o.optInt("width", 0),
                    height = o.optInt("height", 0),
                    iconB64 = o.optString("iconB64", "").ifEmpty { null }
                ))
            }
            list
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun saveInstalledApps(context: Context, apps: List<InstalledAppItem>) {
        val arr = JSONArray()
        apps.take(300).forEach { a ->
            arr.put(JSONObject().apply {
                put("name", a.name)
                put("path", a.path)
                put("iconB64", a.iconB64 ?: "")
            })
        }
        prefs(context).edit { putString(KEY_APPS, arr.toString()) }
    }

    fun getInstalledApps(context: Context): List<InstalledAppItem> {
        val raw = prefs(context).getString(KEY_APPS, null) ?: return emptyList()
        return try {
            val arr = JSONArray(raw)
            val list = mutableListOf<InstalledAppItem>()
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                list.add(InstalledAppItem(
                    name = o.optString("name", ""),
                    path = o.optString("path", ""),
                    iconB64 = o.optString("iconB64", "").ifEmpty { null }
                ))
            }
            list
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun saveAdminTelemetry(context: Context, rawJson: String) {
        try {
            val j = JSONObject(rawJson)
            val tObj = j.optJSONObject("telemetry") ?: j
            val dList = mutableListOf<DiskUsageItem>()
            val dArr = tObj.optJSONArray("disks")
            if (dArr != null) {
                for (i in 0 until dArr.length()) {
                    val d = dArr.getJSONObject(i)
                    dList.add(DiskUsageItem(
                        name = d.optString("name", "C:"),
                        volumeLabel = d.optString("volumeLabel", ""),
                        totalGb = d.optDouble("totalGb", 0.0),
                        freeGb = d.optDouble("freeGb", 0.0),
                        format = d.optString("format", "NTFS")
                    ))
                }
            }
            val nList = mutableListOf<NetworkAdapterItem>()
            val nArr = tObj.optJSONArray("networks")
            if (nArr != null) {
                for (i in 0 until nArr.length()) {
                    val n = nArr.getJSONObject(i)
                    nList.add(NetworkAdapterItem(
                        name = n.optString("name", "Ethernet"),
                        description = n.optString("description", ""),
                        type = n.optString("type", ""),
                        bytesReceived = n.optLong("bytesReceived", 0L),
                        bytesSent = n.optLong("bytesSent", 0L),
                        speedMbps = n.optLong("speedMbps", 0L)
                    ))
                }
            }
            saveAdminTelemetry(context, AdminTelemetry(
                cpuUsage = tObj.optInt("cpuUsage", tObj.optInt("cpuUsagePercent", 0)),
                totalRamMb = tObj.optLong("totalRamMb", tObj.optLong("totalMemoryMb", 0L)),
                availRamMb = tObj.optLong("availRamMb", tObj.optLong("availableMemoryMb", 0L)),
                ramUsagePct = tObj.optInt("ramUsagePct", tObj.optInt("memoryUsagePercent", 0)),
                disks = dList,
                networks = nList,
                gpuName = tObj.optString("gpuName", ""),
                gpuVramMb = tObj.optLong("gpuVramMb", 0L),
                cpuCores = tObj.optInt("cpuCores", 0),
                uptimeSeconds = tObj.optLong("uptimeSeconds", 0L)
            ))
        } catch (_: Exception) {}
    }

    fun saveBatteryHealth(context: Context, rawJson: String) {
        try {
            val j = JSONObject(rawJson)
            val b = j.optJSONObject("batteryHealth") ?: j
            saveBatteryHealth(context, BatteryHealthState(
                designCapacityMwh = b.optDouble("designCapacityMwh", b.optDouble("designedCapacityMwh", 0.0)),
                fullChargeCapacityMwh = b.optDouble("fullChargeCapacityMwh", 0.0),
                wearLevelPct = b.optInt("wearLevelPct", b.optInt("wearLevelPercent", 0)),
                cycleCount = b.optInt("cycleCount", 0)
            ))
        } catch (_: Exception) {}
    }

    fun savePowerPlans(context: Context, rawJson: String) {
        try {
            val arr = JSONArray(rawJson)
            val list = mutableListOf<PowerPlanItem>()
            for (i in 0 until arr.length()) {
                val p = arr.getJSONObject(i)
                list.add(PowerPlanItem(
                    guid = p.optString("guid", ""),
                    name = p.optString("name", "Power Plan"),
                    isActive = p.optBoolean("isActive", false)
                ))
            }
            savePowerPlans(context, list)
        } catch (_: Exception) {}
    }

    fun saveServices(context: Context, rawJson: String) {
        try {
            val arr = JSONArray(rawJson)
            val list = mutableListOf<WindowsServiceItem>()
            for (i in 0 until arr.length()) {
                val s = arr.getJSONObject(i)
                val svcName = s.optString("name", s.optString("serviceName", ""))
                val dispName = s.optString("displayName", svcName)
                list.add(WindowsServiceItem(
                    name = svcName,
                    displayName = if (dispName.isNotBlank()) dispName else svcName,
                    status = s.optString("status", "Stopped"),
                    canStop = s.optBoolean("canStop", true)
                ))
            }
            saveServices(context, list)
        } catch (_: Exception) {}
    }

    fun saveUpdates(context: Context, rawJson: String) {
        try {
            val j = JSONObject(rawJson)
            val u = j.optJSONObject("updates") ?: j
            val tList = mutableListOf<String>()
            val arr = u.optJSONArray("titles")
            if (arr != null) {
                for (i in 0 until arr.length()) {
                    tList.add(arr.getString(i))
                }
            }
            saveUpdates(context, WindowsUpdateState(
                pendingCount = u.optInt("pendingCount", u.optInt("pendingUpdatesCount", 0)),
                isAvailable = u.optBoolean("isAvailable", u.optBoolean("isUpdateAvailable", false)),
                titles = tList
            ))
        } catch (_: Exception) {}
    }

    fun saveRunningWindows(context: Context, rawJson: String) {
        try {
            val arr = JSONArray(rawJson)
            val list = mutableListOf<DesktopWindow>()
            for (i in 0 until arr.length()) {
                val w = arr.getJSONObject(i)
                list.add(DesktopWindow(
                    hwnd = w.optLong("hwnd", 0L),
                    title = w.optString("title", ""),
                    processName = w.optString("processName", ""),
                    processId = w.optInt("processId", 0),
                    width = w.optInt("width", 0),
                    height = w.optInt("height", 0),
                    iconB64 = w.optString("iconB64", "").ifEmpty { null }
                ))
            }
            saveWindows(context, list)
        } catch (_: Exception) {}
    }

    fun saveInstalledApps(context: Context, rawJson: String) {
        try {
            val arr = JSONArray(rawJson)
            val list = mutableListOf<InstalledAppItem>()
            for (i in 0 until arr.length()) {
                val a = arr.getJSONObject(i)
                list.add(InstalledAppItem(
                    name = a.optString("name", ""),
                    path = a.optString("path", ""),
                    iconB64 = a.optString("iconB64", "").ifEmpty { null }
                ))
            }
            saveInstalledApps(context, list)
        } catch (_: Exception) {}
    }

    fun saveHardwareMetrics(context: Context, rawJson: String) {
        try {
            val j = JSONObject(rawJson)
            val vol = j.optInt("volumeLevel", -1)
            val bright = j.optInt("brightnessLevel", -1)
            saveMetrics(context, vol, bright)
        } catch (_: Exception) {}
    }
}
