# Tether Proximity Shield - Optimized R8/ProGuard Rules

# 1. Keep BLE Service and related GATT components
-keep class com.tether.phone.BleGattServerService { *; }
-keep class com.tether.phone.BleGattServerService$* { *; }

# 2. Keep Security Engine and Keystore interactions
# Obfuscation can break Keystore alias lookups or reflection-based cryptographic providers
-keep class com.tether.phone.ProductionSecurityEngine { *; }
-keep class android.security.keystore.** { *; }

# 3. ZXing (QR Generation) Rules
-keep class com.google.zxing.** { *; }
-dontwarn com.google.zxing.**

# 4. BouncyCastle / Cryptography Rules
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**
-dontwarn javax.crypto.**

# 5. Jetpack Compose and Material 3
# Usually handled by default rules, but explicitly keeping UI state classes
-keep class com.tether.phone.ui.theme.** { *; }
-keep class com.tether.phone.MainActivity { *; }

# 6. Lifecycle and Coroutines
-keep class kotlinx.coroutines.** { *; }

# 7. Preserve line numbers and source files for meaningful crash reports
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
