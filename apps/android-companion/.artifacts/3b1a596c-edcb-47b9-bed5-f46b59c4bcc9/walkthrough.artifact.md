# Walkthrough - Manual Server Restart

I have implemented a "Restart Server" feature that allows users to manually refresh the BLE GATT server and advertising stack. This is useful for resolving occasional connectivity issues without needing to restart the entire app or toggle system Bluetooth.

## Changes Made

### BLE Service Enhancements
- Added `ACTION_RESTART_SERVER` to [BleGattServerService.kt](file:///C:/Dev/Tether/apps/android-companion/app/src/main/java/com/tether/phone/BleGattServerService.kt).
- Implemented handler in `onStartCommand` to trigger a deep refresh of the GATT server using the existing `restartGattServer()` logic.

### UI Integration
- Added `restartBleServer()` to [MainActivity.kt](file:///C:/Dev/Tether/apps/android-companion/app/src/main/java/com/tether/phone/MainActivity.kt) which sends the restart intent to the service.
- Updated `TetherNavigationShell` and `SettingsScreen` in [MainScreens.kt](file:///C:/Dev/Tether/apps/android-companion/app/src/main/java/com/tether/phone/ui/screens/MainScreens.kt) to include the new button.

### User Interface
- A new **Service Control** section has been added to the **Settings** screen.
- Includes a **Restart Server** button with a refresh icon.
- Tapping the button updates the connection status to "RESTARTING SECURE STACK..." and triggers the refresh.

## Verification Results

### Automated Tests
- Ran `:app:assembleDebug` - Build successful.

### Manual Verification Path
1. Launch the Tether Companion app.
2. Navigate to the **Settings** screen via the side drawer.
3. Scroll down to the **Service Control** section.
4. Tap **RESTART SERVER**.
5. Observe the service notification briefly update and the connection status reflect the restart.
