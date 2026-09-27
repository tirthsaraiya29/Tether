@file:Suppress("unused")

package com.tether.phone

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.core.content.edit
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.KeyPairGenerator
import java.security.cert.X509Certificate
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.security.auth.x500.X500Principal

/**
 * Core cryptographic engine for Tether Android Companion.
 * Uses AndroidKeyStore for hardware-backed long-lived EC identity keys,
 * AES-256 GCM hardware key storage for pinned Windows identities,
 * self-signed X.509 certificate retrieval, and SHA-256 fingerprinting.
 */
class ProductionSecurityEngine {

    companion object {
        private const val TAG = "ProductionSecurityEngine"
        private const val EC_IDENTITY_ALIAS = "TetherIdentityKey_v1"
        private const val STORAGE_KEY_ALIAS = "TetherStorageKey_v2"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val PREFS_NAME = "tether_secure_prefs"
        private const val PINNED_WINDOWS_KEY_PREF = "pinned_windows_public_key_enc"
        private const val PINNED_WINDOWS_PQC_KEM_PREF = "pinned_windows_pqc_kem_pub_enc"
        private const val PINNED_WINDOWS_PQC_DSA_PREF = "pinned_windows_pqc_dsa_pub_enc"
        private const val LOCAL_PQC_KEM_PUB_PREF = "local_pqc_kem_pub_enc"
        private const val LOCAL_PQC_KEM_PRIV_PREF = "local_pqc_kem_priv_enc"
        private const val LOCAL_PQC_DSA_PUB_PREF = "local_pqc_dsa_pub_enc"
        private const val LOCAL_PQC_DSA_PRIV_PREF = "local_pqc_dsa_priv_enc"
    }

    @Volatile
    private var cachedPqcKeyPair: PqcKeyPair? = null

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
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
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
                ANDROID_KEYSTORE
            )
            val parameterSpec = KeyGenParameterSpec.Builder(
                STORAGE_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()

            keyGenerator.init(parameterSpec)
            keyGenerator.generateKey()
        }
    }

    fun getIdentityPrivateKey(): PrivateKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return keyStore.getKey(EC_IDENTITY_ALIAS, null) as PrivateKey
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
        ensureStorageKeyExists()
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val secretKey = keyStore.getKey(STORAGE_KEY_ALIAS, null) as SecretKey

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv
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
            if (combined.size <= 12) return null
            val iv = combined.copyOfRange(0, 12)
            val ciphertext = combined.copyOfRange(12, combined.size)

            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            val secretKey = keyStore.getKey(STORAGE_KEY_ALIAS, null) as SecretKey

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val spec = GCMParameterSpec(128, iv)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
            cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to decrypt string: ${e.message}")
            null
        }
    }

    fun getOrCreatePqcKeyPair(context: Context): PqcKeyPair {
        cachedPqcKeyPair?.let { return it }

        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val kemPubEnc = prefs.getString(LOCAL_PQC_KEM_PUB_PREF, null)
        val kemPrivEnc = prefs.getString(LOCAL_PQC_KEM_PRIV_PREF, null)
        val dsaPubEnc = prefs.getString(LOCAL_PQC_DSA_PUB_PREF, null)
        val dsaPrivEnc = prefs.getString(LOCAL_PQC_DSA_PRIV_PREF, null)

        val kemPub = decryptString(kemPubEnc)
        val kemPriv = decryptString(kemPrivEnc)
        val dsaPub = decryptString(dsaPubEnc)
        val dsaPriv = decryptString(dsaPrivEnc)

        if ((kemPub != null) && (kemPriv != null) && (dsaPub != null) && (dsaPriv != null)) {
            val keyPair = PqcKeyPair(kemPub, kemPriv, dsaPub, dsaPriv)
            cachedPqcKeyPair = keyPair
            return keyPair
        }

        Log.i(TAG, "Generating long-lived PQC identity keypair (ML-KEM-768 + ML-DSA-65)...")
        val newKeyPair = PqcHandshake.generateKeyPair()
        prefs.edit {
            putString(LOCAL_PQC_KEM_PUB_PREF, encryptBytes(newKeyPair.kemPublicKey))
            putString(LOCAL_PQC_KEM_PRIV_PREF, encryptBytes(newKeyPair.kemPrivateKey))
            putString(LOCAL_PQC_DSA_PUB_PREF, encryptBytes(newKeyPair.dsaPublicKey))
            putString(LOCAL_PQC_DSA_PRIV_PREF, encryptBytes(newKeyPair.dsaPrivateKey))
        }
        cachedPqcKeyPair = newKeyPair
        return newKeyPair
    }

    fun getPqcKemPublicKeyBytes(context: Context): ByteArray {
        return getOrCreatePqcKeyPair(context).kemPublicKey
    }

    fun getPqcDsaPublicKeyBytes(context: Context): ByteArray {
        return getOrCreatePqcKeyPair(context).dsaPublicKey
    }

    fun storePinnedWindowsPqcKeys(context: Context, kemPub: ByteArray, dsaPub: ByteArray) {
        try {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            prefs.edit {
                putString(PINNED_WINDOWS_PQC_KEM_PREF, encryptBytes(kemPub))
                putString(PINNED_WINDOWS_PQC_DSA_PREF, encryptBytes(dsaPub))
            }
            Log.i(TAG, "Pinned Windows PQC public keys stored securely.")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to store pinned Windows PQC keys: ${e.message}", e)
        }
    }

    fun getPinnedWindowsPqcKeys(context: Context): Pair<ByteArray, ByteArray>? {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val kemEnc = prefs.getString(PINNED_WINDOWS_PQC_KEM_PREF, null)
        val dsaEnc = prefs.getString(PINNED_WINDOWS_PQC_DSA_PREF, null)

        val kemPub = decryptString(kemEnc)
        val dsaPub = decryptString(dsaEnc)

        return if (kemPub != null && dsaPub != null) {
            Pair(kemPub, dsaPub)
        } else {
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
                remove(PINNED_WINDOWS_PQC_KEM_PREF)
                remove(PINNED_WINDOWS_PQC_DSA_PREF)
            }
            Log.i(TAG, "Cleared pinned Windows public keys from storage.")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to clear pinned keys: ${e.message}", e)
        }
    }

    fun computePublicKeyFingerprint(publicKeyBytes: ByteArray?): String {
        if (publicKeyBytes == null || publicKeyBytes.isEmpty()) return "NONE"
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
