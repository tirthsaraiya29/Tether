# Walkthrough - Service Persistence Fix

I have implemented several changes to ensure that the Tether broadcasting service remains active in the background and restarts automatically if terminated by the system or swiped away by the user.

## Changes Made

### 1. Robust Service Restart on Swipe
Added `onTaskRemoved` to `BleGattServerService.kt`. When the user swipes the app away from the recents list, the service now schedules an immediate restart (after 1 second) via `AlarmManager`.

### 2. Manifest-Declared Health Check Receiver
Created [TetherServiceReceiver.kt](file:///C:/Dev/Tether/apps/android-companion/app/src/main/java/com/tether/phone/TetherServiceReceiver.kt) and registered it in the [AndroidManifest.xml](file:///C:/Dev/Tether/apps/android-companion/app/src/main/AndroidManifest.xml).
- This receiver catches the health check alarm even if the app process has been killed.
- It pings the `BleGattServerService` to ensure it's running and performing its regular health checks.

### 3. Strengthened Alarms
Updated `scheduleAlarmForHealthCheck` in `BleGattServerService.kt`:
- Now uses `setAndAllowWhileIdle` (on API 23+), ensuring the alarm fires even when the device is in Doze mode.
- Targets the manifest receiver instead of a dynamic listener, allowing for process restarts.

### 4. Start on Phone Boot
- Added `RECEIVE_BOOT_COMPLETED` permission.
- Configured `TetherServiceReceiver` to handle `ACTION_BOOT_COMPLETED` and `ACTION_LOCKED_BOOT_COMPLETED`.
- Enabled `directBootAware="true"` for both the service and receiver, allowing them to start as early as possible after a reboot.
- This ensures Tether is active and ready to broadcast as soon as the phone starts up.

### 5. Future Compatibility (Android 16/17)
- Target SDK and Compile SDK are set to 37, covering anticipated requirements for Android 16/17.
- Used modern foreground service types (`connectedDevice`) and `PendingIntent` flags (`FLAG_IMMUTABLE`) to ensure compliance with strict background policies in newer Android versions.

## Verification Results

### Deployment
The app was successfully built and deployed to the device `RZGYC0KFR5X`.

### Behavior
- **Foreground Service**: The notification remains active.
- **Swipe Protection**: Swiping the app away should no longer kill the broadcasting definitively; the service will restart itself.
- **Background Longevity**: The manifest receiver and "allow while idle" alarms provide a safety net against process termination by the Android OS.

> [!IMPORTANT]
> Even with these changes, some aggressive OEM power management (like Samsung's "Deep Sleeping Apps") might still interfere. Since you've already excluded the app from battery optimizations in OneUI, these code-level enhancements should provide the highest possible reliability.
