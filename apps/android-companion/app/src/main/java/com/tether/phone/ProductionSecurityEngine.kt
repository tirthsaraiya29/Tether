package com.tether.phone

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.biometric.BiometricPrompt
import androidx.core.content.edit
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.X509Certificate
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.security.auth.x500.X500Principal

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
    }

    init {
        ensureIdentityKeyPairExists()
        ensureStorageKeyExists()
    }

    private fun ensureIdentityKeyPairExists() {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (!keyStore.containsAlias(EC_IDENTITY_ALIAS)) {
            Log.i(TAG, "Generating new hardware-backed EC identity key pair in AndroidKeyStore...")
            val kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                ANDROID_KEYSTORE,
            )

            val parameterSpec = KeyGenParameterSpec.Builder(
                EC_IDENTITY_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            )
                .setCertificateSubject(X500Principal("CN=TetherAndroidDevice, O=Tether, OU=Mobile"))
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setKeySize(256)
                .build()

            kpg.initialize(parameterSpec)
            kpg.generateKeyPair()
            Log.i(TAG, "EC identity key pair successfully created.")
        }
    }

    private fun ensureStorageKeyExists() {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (!keyStore.containsAlias(STORAGE_KEY_ALIAS)) {
            Log.i(TAG, "Generating hardware AES-256 storage key in AndroidKeyStore...")
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE,
            )
            val parameterSpec = KeyGenParameterSpec.Builder(
                STORAGE_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()

            keyGenerator.init(parameterSpec)
            keyGenerator.generateKey()
        }
    }

    private fun newRandomGcmIv(): ByteArray {
        val iv = ByteArray(GCM_IV_LENGTH_BYTES)
        SecureRandom().nextBytes(iv)
        return iv
    }

    private fun newGcmCipher(): Cipher =
        Cipher.getInstance("AES/GCM/NoPadding")

    private fun loadStorageKey(): SecretKey {
        ensureStorageKeyExists()
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return keyStore.getKey(STORAGE_KEY_ALIAS, null) as SecretKey
    }

    fun getIdentityPrivateKey(): PrivateKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return keyStore.getKey(EC_IDENTITY_ALIAS, null) as PrivateKey
    }

    fun createCryptoObjectForAuthentication(): BiometricPrompt.CryptoObject? {
        return try {
            val secretKey = loadStorageKey()
            val iv = newRandomGcmIv()

            val cipher = newGcmCipher()
            val spec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec)
            BiometricPrompt.CryptoObject(cipher)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create CryptoObject for biometric auth: ${e.message}")
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
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val cert = keyStore.getCertificate(EC_IDENTITY_ALIAS)
        return (cert as? X509Certificate)
            ?: throw IllegalStateException("Failed to load X509Certificate for alias $EC_IDENTITY_ALIAS")
    }

    fun getIdentityPublicKeyBytes(): ByteArray {
        return getIdentityCertificate().publicKey.encoded
    }

    private fun encryptBytes(data: ByteArray): String {
        val secretKey = loadStorageKey()
        val iv = newRandomGcmIv()

        val cipher = newGcmCipher()
        val spec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec)
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

    fun storePinnedKeySecurely(context: Context, publicKeyBytes: ByteArray) {
        try {
            val encodedStr = encryptBytes(publicKeyBytes)
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            prefs.edit { putString(PINNED_WINDOWS_KEY_PREF, encodedStr) }
            Log.i(TAG, "Pinned Windows public identity key encrypted and saved to secure storage.")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to store pinned key securely: ${e.message}", e)
        }
    }

    fun getPinnedKeyDecrypted(context: Context): ByteArray? {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val encodedStr = prefs.getString(PINNED_WINDOWS_KEY_PREF, null)
        return decryptString(encodedStr)
    }

    fun clearPinnedKey(context: Context) {
        try {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            prefs.edit {
                remove(PINNED_WINDOWS_KEY_PREF)
            }
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