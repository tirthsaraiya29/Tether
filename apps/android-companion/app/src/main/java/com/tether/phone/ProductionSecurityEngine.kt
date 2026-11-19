package com.tether.phone

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.biometric.BiometricPrompt
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.cert.X509Certificate
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.security.auth.x500.X500Principal

sealed class PinnedKeyResult {
    object Unprovisioned : PinnedKeyResult()
    data class Present(val keyBytes: ByteArray) : PinnedKeyResult() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Present) return false
            return keyBytes.contentEquals(other.keyBytes)
        }
        override fun hashCode(): Int = keyBytes.contentHashCode()
    }
    data class Corrupted(val exception: Throwable? = null) : PinnedKeyResult()
}

class ProductionSecurityEngine {

    companion object {
        private const val TAG = "ProductionSecurityEngine"
        private const val EC_IDENTITY_ALIAS = "TetherIdentityKey_v1"
        private const val STORAGE_KEY_ALIAS = "TetherStorageKey_v2"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val PREFS_NAME = "tether_secure_prefs"
        private const val PINNED_WINDOWS_KEY_PREF = "pinned_windows_public_key_enc"

        private const val GCM_IV_LENGTH_BYTES = 12
        private const val GCM_TAG_LENGTH_BITS = 128

        private val keyCacheLock = Any()

        @Volatile
        private var cachedPublicKeyBytes: ByteArray? = null
        @Volatile
        private var cachedPinnedKeyBytes: ByteArray? = null
        @Volatile
        private var cachedPinnedKeyResult: PinnedKeyResult? = null
        @Volatile
        private var pinnedKeyLoaded = false
    }

    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }

    @Synchronized
    private fun ensureIdentityKeyPairExists() {
        if (keyStore.containsAlias(EC_IDENTITY_ALIAS)) {
            try {
                val privateKey = keyStore.getKey(EC_IDENTITY_ALIAS, null) as? PrivateKey
                if (privateKey != null) {
                    val testSig = Signature.getInstance("SHA256withECDSA")
                    testSig.initSign(privateKey)
                    testSig.update(byteArrayOf(1, 2, 3))
                    testSig.sign()
                } else {
                    keyStore.deleteEntry(EC_IDENTITY_ALIAS)
                    cachedPublicKeyBytes = null
                }
            } catch (_: Exception) {
                try {
                    keyStore.deleteEntry(EC_IDENTITY_ALIAS)
                    cachedPublicKeyBytes = null
                } catch (_: Exception) {}
            }
        }

        if (!keyStore.containsAlias(EC_IDENTITY_ALIAS)) {
            Log.i(TAG, "Generating new hardware-backed EC identity key pair in AndroidKeyStore...")
            val kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                ANDROID_KEYSTORE,
            )

            fun createSpec(useStrongBox: Boolean): KeyGenParameterSpec {
                val builder = KeyGenParameterSpec.Builder(
                    EC_IDENTITY_ALIAS,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                )
                    .setCertificateSubject(X500Principal("CN=TetherAndroidDevice, O=Tether, OU=Mobile"))
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    .setKeySize(256)
                    .setUserAuthenticationRequired(true)

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    builder.setUserAuthenticationParameters(
                        0,
                        KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
                    )
                } else {
                    builder.setUserAuthenticationValidityDurationSeconds(-1)
                }

                if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    builder.setIsStrongBoxBacked(true)
                }
                return builder.build()
            }

            try {
                kpg.initialize(createSpec(useStrongBox = true))
                kpg.generateKeyPair()
                Log.i(TAG, "EC identity key pair successfully created in hardware enclave (StrongBox preference).")
            } catch (e: Exception) {
                Log.w(TAG, "StrongBox unavailable for identity key (${e.message}); using standard AndroidKeyStore TEE...")
                kpg.initialize(createSpec(useStrongBox = false))
                kpg.generateKeyPair()
                Log.i(TAG, "EC identity key pair successfully created in AndroidKeyStore.")
            }
            cachedPublicKeyBytes = null
        }
    }

    @Synchronized
    private fun ensureStorageKeyExists() {
        if (!keyStore.containsAlias(STORAGE_KEY_ALIAS)) {
            Log.i(TAG, "Generating hardware AES-256 storage key in AndroidKeyStore...")
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE,
            )

            fun createStorageSpec(useStrongBox: Boolean): KeyGenParameterSpec {
                val builder = KeyGenParameterSpec.Builder(
                    STORAGE_KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(true)
                    .setKeySize(256)

                if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    builder.setIsStrongBoxBacked(true)
                }
                return builder.build()
            }

            try {
                keyGenerator.init(createStorageSpec(useStrongBox = true))
                keyGenerator.generateKey()
                Log.i(TAG, "AES-256 storage key successfully created with StrongBox preference.")
            } catch (e: Exception) {
                Log.w(TAG, "StrongBox unavailable for storage key (${e.message}); using standard AndroidKeyStore TEE...")
                keyGenerator.init(createStorageSpec(useStrongBox = false))
                keyGenerator.generateKey()
            }
        }
    }

    private fun newGcmCipher(): Cipher = Cipher.getInstance("AES/GCM/NoPadding")

    private fun loadStorageKey(): SecretKey {
        ensureStorageKeyExists()
        return keyStore.getKey(STORAGE_KEY_ALIAS, null) as SecretKey
    }

    fun getIdentityPrivateKey(): PrivateKey {
        ensureIdentityKeyPairExists()
        return keyStore.getKey(EC_IDENTITY_ALIAS, null) as PrivateKey
    }

    fun createCryptoObjectForAuthentication(): BiometricPrompt.CryptoObject? {
        return try {
            val secretKey = loadStorageKey()
            val cipher = newGcmCipher()
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            BiometricPrompt.CryptoObject(cipher)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create CryptoObject for biometric auth: ${e.message}")
            null
        }
    }

    fun createSignatureCryptoObject(): BiometricPrompt.CryptoObject? {
        return try {
            ensureIdentityKeyPairExists()
            val privateKey = keyStore.getKey(EC_IDENTITY_ALIAS, null) as? PrivateKey
                ?: return null
            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initSign(privateKey)
            BiometricPrompt.CryptoObject(signature)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create Signature CryptoObject: ${e.message}")
            null
        }
    }

    fun signWithIdentityKey(data: ByteArray): ByteArray {
        val privateKey = getIdentityPrivateKey()
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(privateKey)
        signature.update(data)
        return signature.sign()
    }

    fun getIdentityCertificate(): X509Certificate {
        ensureIdentityKeyPairExists()
        val cert = keyStore.getCertificate(EC_IDENTITY_ALIAS)
        return (cert as? X509Certificate)
            ?: throw IllegalStateException("Failed to load X509Certificate for alias $EC_IDENTITY_ALIAS")
    }

    fun getIdentityPublicKeyBytes(): ByteArray {
        cachedPublicKeyBytes?.let { return it }
        val bytes = getIdentityCertificate().publicKey.encoded
        cachedPublicKeyBytes = bytes
        return bytes
    }

    private fun encryptBytes(data: ByteArray): String {
        val secretKey = loadStorageKey()
        val cipher = newGcmCipher()
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv ?: throw IllegalStateException("Cipher failed to generate IV")
        val encryptedBytes = cipher.doFinal(data)

        val combined = ByteArray(iv.size + encryptedBytes.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(encryptedBytes, 0, combined, iv.size, encryptedBytes.size)

        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    private fun decryptString(encodedStr: String?): ByteArray? {
        if (encodedStr.isNullOrBlank()) return null
        return try {
            val combined = Base64.decode(encodedStr, Base64.NO_WRAP)
            if (combined.size <= GCM_IV_LENGTH_BYTES) return null
            val iv = combined.copyOfRange(0, GCM_IV_LENGTH_BYTES)
            val ciphertext = combined.copyOfRange(GCM_IV_LENGTH_BYTES, combined.size)

            val secretKey = loadStorageKey()
            val cipher = newGcmCipher()
            val spec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
            cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to decrypt string: ${e.message}")
            null
        }
    }

    fun getPinnedKeyResult(context: Context): PinnedKeyResult = synchronized(keyCacheLock) {
        cachedPinnedKeyResult?.let { cached ->
            return@synchronized when (cached) {
                is PinnedKeyResult.Present -> PinnedKeyResult.Present(cached.keyBytes.copyOf())
                else -> cached
            }
        }

        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        if (!prefs.contains(PINNED_WINDOWS_KEY_PREF)) {
            val result = PinnedKeyResult.Unprovisioned
            cachedPinnedKeyResult = result
            return@synchronized result
        }

        val encodedStr = prefs.getString(PINNED_WINDOWS_KEY_PREF, null)
        if (encodedStr.isNullOrBlank()) {
            val result = PinnedKeyResult.Unprovisioned
            cachedPinnedKeyResult = result
            return@synchronized result
        }

        return@synchronized try {
            val decrypted = decryptString(encodedStr)
            if (decrypted != null && decrypted.isNotEmpty()) {
                val result = PinnedKeyResult.Present(decrypted)
                cachedPinnedKeyResult = result
                result
            } else {
                Log.e(TAG, "Decrypted pinned key is null or empty, treating stored pin as corrupted.")
                val result = PinnedKeyResult.Corrupted(IllegalStateException("Decryption returned empty pin data"))
                cachedPinnedKeyResult = result
                result
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to decrypt pinned key from storage: ${e.message}", e)
            val result = PinnedKeyResult.Corrupted(e)
            cachedPinnedKeyResult = result
            result
        }
    }

    fun storePinnedKeySecurely(context: Context, publicKeyBytes: ByteArray): Boolean = synchronized(keyCacheLock) {
        try {
            cachedPinnedKeyResult = null
            val encodedStr = encryptBytes(publicKeyBytes)
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val committed = prefs.edit().putString(PINNED_WINDOWS_KEY_PREF, encodedStr).commit()
            if (!committed) {
                Log.e(TAG, "Failed committing pinned Windows key to storage")
                return@synchronized false
            }

            val readBackResult = getPinnedKeyResult(context)
            if (readBackResult !is PinnedKeyResult.Present || !MessageDigest.isEqual(readBackResult.keyBytes, publicKeyBytes)) {
                Log.e(TAG, "Read-back verification of pinned Windows key failed")
                return@synchronized false
            }

            Log.i(TAG, "Pinned Windows public identity key encrypted, saved, and verified in secure storage.")
            cachedPinnedKeyResult = PinnedKeyResult.Present(publicKeyBytes.copyOf())
            cachedPinnedKeyBytes = publicKeyBytes.copyOf()
            pinnedKeyLoaded = true
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to store pinned key securely: ${e.message}", e)
            false
        }
    }

    fun getPinnedKeyDecrypted(context: Context): ByteArray? = synchronized(keyCacheLock) {
        when (val result = getPinnedKeyResult(context)) {
            is PinnedKeyResult.Present -> result.keyBytes.copyOf()
            is PinnedKeyResult.Unprovisioned -> null
            is PinnedKeyResult.Corrupted -> throw SecurityException(
                "Stored pinned key is corrupted or cannot be decrypted",
                result.exception
            )
        }
    }

    fun clearPinnedKey(context: Context) = synchronized(keyCacheLock) {
        try {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            prefs.edit().remove(PINNED_WINDOWS_KEY_PREF).apply()
            cachedPinnedKeyBytes = null
            cachedPinnedKeyResult = PinnedKeyResult.Unprovisioned
            pinnedKeyLoaded = false
            FileTransferClient.clearCache()
            Log.i(TAG, "Cleared pinned Windows public keys from storage.")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to clear pinned keys: ${e.message}", e)
        }
    }

    fun computePublicKeyFingerprint(publicKeyBytes: ByteArray?): String {
        if ((publicKeyBytes == null) || publicKeyBytes.isEmpty()) return "NONE"
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            val hash = digest.digest(publicKeyBytes)
            hash.joinToString(":") { String.format(Locale.US, "%02X", it) }
        } catch (_: Exception) {
            "INVALID"
        }
    }

    fun getPublicKeyBytes(): ByteArray {
        return getIdentityPublicKeyBytes()
    }
}