# Implementation Plan - Enable Start on Boot and Android 16/17 Compatibility

The goal is to ensure the Tether broadcasting service starts automatically when the phone is powered on or restarted. We also aim to maintain compatibility with future Android versions (up to Android 16/17).

## Proposed Changes

### [Component: Manifest Configuration]

#### [MODIFY] [AndroidManifest.xml](file:///C:/Dev/Tether/apps/android-companion/app/src/main/AndroidManifest.xml)
- Add the `RECEIVE_BOOT_COMPLETED` permission.
- Update the `TetherServiceReceiver` to handle `Intent.ACTION_BOOT_COMPLETED` and `Intent.ACTION_LOCKED_BOOT_COMPLETED`.
- Enable `android:directBootAware="true"` for both the `BleGattServerService` and `TetherServiceReceiver` to allow starting before the initial user unlock (Direct Boot).

### [Component: Broadcast Receiver]

#### [MODIFY] [TetherServiceReceiver.kt](file:///C:/Dev/Tether/apps/android-companion/app/src/main/java/com/tether/phone/TetherServiceReceiver.kt)
- Update `onReceive` to handle `Intent.ACTION_BOOT_COMPLETED` and `Intent.ACTION_LOCKED_BOOT_COMPLETED`.
- When these actions are received, trigger the service with a "ping" action to start it.

### [Component: Core Service]

#### [MODIFY] [BleGattServerService.kt](file:///C:/Dev/Tether/apps/android-companion/app/src/main/java/com/tether/phone/BleGattServerService.kt)
- Ensure the service can handle being started in a "locked" state (Direct Boot).
- Since the service uses `SharedPreferences`, we should ensure it uses the correct context for device-protected storage if necessary, or simply allow it to start and wait for the credential-protected storage to be available if boot-start is enough.
- *Decision*: We will stick to standard boot completion for now unless Direct Boot is explicitly required for "phone start" without unlock. However, enabling `directBootAware` is generally safer for "start on boot" apps to ensure they aren't delayed by system encryption states.

## Verification Plan

### Automated Tests
- No automated tests available for boot behavior.

### Manual Verification
1. Deploy the app.
2. Ensure broadcasting is enabled.
3. Restart the phone.
4. Verify that the Tether notification appears shortly after the phone boots up (without needing to open the app manually).
5. Verify that broadcasting is active on the host (Windows).
