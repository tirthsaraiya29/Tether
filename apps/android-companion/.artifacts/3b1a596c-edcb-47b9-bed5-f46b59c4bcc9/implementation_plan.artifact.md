# Implementation Plan - Restart Server Service & Bluetooth Refresh

Add a button to the companion app that allows users to manually restart the BLE GATT server and advertising. This action will also attempt to "refresh" the Bluetooth stack by purging existing GATT handles and re-initializing the server infrastructure.

## User Review Required

> [!IMPORTANT]
> **Connection Interruption**: Restarting the GATT server will TEMPORARILY disconnect any active sessions. The laptop client must be configured to auto-reconnect (which it should by default if it follows the BLE specifications used in this project).
>
> **Bluetooth Toggle Limitation**: On Android 13+ (API 33+), apps cannot programmatically toggle the system Bluetooth switch. The "refresh" logic will focus on a full restart of the GATT server and advertising stack, which effectively solves most "stuck" connection issues without requiring system-level permissions that are restricted in production.

## Proposed Changes

### [Component] BLE Service logic

#### [MODIFY] [BleGattServerService.kt](file:///C:/Dev/Tether/apps/android-companion/app/src/main/java/com/tether/phone/BleGattServerService.kt)
- Add `ACTION_RESTART_SERVER` constant.
- Handle `ACTION_RESTART_SERVER` in `onStartCommand` to trigger `restartGattServer()`.

### [Component] UI Integration

#### [MODIFY] [MainActivity.kt](file:///C:/Dev/Tether/apps/android-companion/app/src/main/java/com/tether/phone/MainActivity.kt)
- Implement `restartBleServer()` helper method.
- Pass `onRestartServer` callback through `TetherNavigationShell`.

#### [MODIFY] [MainScreens.kt](file:///C:/Dev/Tether/apps/android-companion/app/src/main/java/com/tether/phone/ui/screens/MainScreens.kt)
- Add a "Service Management" section to `SettingsScreen`.
- Include a "Restart Server" button with a visual "refresh" icon.

## Verification Plan

### Manual Verification
1. Open the app and navigate to **Settings**.
2. Tap the **Restart Server** button.
3. Observe the service notification restarting and Bluetooth advertising resuming (can be verified with a BLE scanner or by checking the laptop client's reconnection behavior).
4. Verify that existing connections are cleanly closed and new ones can be established.
