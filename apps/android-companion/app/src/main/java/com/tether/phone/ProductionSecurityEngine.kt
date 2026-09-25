package com.tether.phone

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.core.content.edit
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

class ProductionSecurityEngine {

    companion object {
        private const val KEY_ALIAS = "TetherAsymmetricKey_v4"
        private const val OLD_KEY_ALIAS = "TetherAsymmetricKey_v3"
        private const val STORAGE_KEY_ALIAS = "TetherStorageKey_v1"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }

    init {
        ensureKeyPairExists()
        ensureStorageKeyExists()
    }

    private fun ensureKeyPairExists() {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

        // Purge legacy key without SHA-1 authorization
        if (keyStore.containsAlias(OLD_KEY_ALIAS)) {
            try {
                keyStore.deleteEntry(OLD_KEY_ALIAS)
                Log.i("TetherSecurity", "Purged obsolete keystore alias $OLD_KEY_ALIAS")
            } catch (e: Exception) {
                Log.w("TetherSecurity", "Could not purge old alias: ${e.message}")
            }
        }

        if (!keyStore.containsAlias(KEY_ALIAS)) {
            val kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA,
                ANDROID_KEYSTORE,
            )

            val parameterSpec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY or KeyProperties.PURPOSE_DECRYPT,
            )
                // DIGEST_SHA1 is mandatory for interoperating with standard RSA-OAEP implementations
                .setDigests(
                    KeyProperties.DIGEST_SHA1,
                    KeyProperties.DIGEST_SHA256,
                    KeyProperties.DIGEST_SHA512
                )
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setKeySize(2048)
                .build()

            kpg.initialize(parameterSpec)
            kpg.generateKeyPair()
            Log.i("TetherSecurity", "Generated new asymmetric hardware keypair under alias $KEY_ALIAS")
        }
    }

    private fun ensureStorageKeyExists() {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (!keyStore.containsAlias(STORAGE_KEY_ALIAS)) {
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

    fun storePinnedKeySecurely(context: Context, publicKeyBytes: ByteArray) {
        try {
            ensureStorageKeyExists()
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            val secretKey = keyStore.getKey(STORAGE_KEY_ALIAS, null) as SecretKey

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            val iv = cipher.iv
            val encryptedBytes = cipher.doFinal(publicKeyBytes)

            val combined = ByteArray(iv.size + encryptedBytes.size)
            System.arraycopy(iv, 0, combined, 0, iv.size)
            System.arraycopy(encryptedBytes, 0, combined, iv.size, encryptedBytes.size)

            val encodedStr = Base64.encodeToString(combined, Base64.NO_WRAP)
            val prefs = context.getSharedPreferences("tether_secure_prefs", Context.MODE_PRIVATE)
            prefs.edit { putString("pinned_windows_public_key_enc", encodedStr) }
            Log.i("TetherSecurity", "Public key encrypted with hardware AES key and persisted successfully.")
        } catch (e: Exception) {
            Log.e("TetherSecurity", "Failed to encrypt and store public key securely: ${e.message}", e)
        }
    }

    fun getPinnedKeyDecrypted(context: Context): ByteArray? {
        try {
            val prefs = context.getSharedPreferences("tether_secure_prefs", Context.MODE_PRIVATE)
            val encodedStr = prefs.getString("pinned_windows_public_key_enc", null) ?: return null
            val combined = Base64.decode(encodedStr, Base64.NO_WRAP)

            if (combined.size <= 12) return null
            val iv = combined.copyOfRange(0, 12)
            val ciphertext = combined.copyOfRange(12, combined.size)

            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            val secretKey = keyStore.getKey(STORAGE_KEY_ALIAS, null) as SecretKey

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val spec = GCMParameterSpec(128, iv)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
            return cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            Log.e("TetherSecurity", "Failed to decrypt and retrieve pinned public key: ${e.message}", e)
            return null
        }
    }

    fun clearPinnedKey(context: Context) {
        try {
            val prefs = context.getSharedPreferences("tether_secure_prefs", Context.MODE_PRIVATE)
            prefs.edit { remove("pinned_windows_public_key_enc") }
            Log.i("TetherSecurity", "Pinned public key unpinned/cleared.")
        } catch (e: Exception) {
            Log.e("TetherSecurity", "Failed to clear pinned public key: ${e.message}", e)
        }
    }

    fun getPublicKeyBytes(): ByteArray {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val publicKey = keyStore.getCertificate(KEY_ALIAS).publicKey
        return publicKey.encoded
    }

    fun decryptSessionKey(encryptedKey: ByteArray): ByteArray {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val privateKeyEntry = keyStore.getEntry(KEY_ALIAS, null) as KeyStore.PrivateKeyEntry
        val privateKey = privateKeyEntry.privateKey

        val attempts = listOf(
            // 1. Standard PKCS#1 v2.1 OAEP with SHA-1/MGF1-SHA1 (.NET default)
            {
                val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding")
                cipher.init(Cipher.DECRYPT_MODE, privateKey)
                cipher.doFinal(encryptedKey)
            },
            // 2. Generic OAEPPadding alias
            {
                val cipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
                cipher.init(Cipher.DECRYPT_MODE, privateKey)
                cipher.doFinal(encryptedKey)
            },
            // 3. Explicit OAEPParameterSpec (SHA-1)
            {
                val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding")
                val spec = OAEPParameterSpec(
                    "SHA-1", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT,
                )
                cipher.init(Cipher.DECRYPT_MODE, privateKey, spec)
                cipher.doFinal(encryptedKey)
            },
            // 4. SHA-256 fallback (Keymaster standard MGF1-SHA1)
            {
                val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
                val spec = OAEPParameterSpec(
                    "SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT,
                )
                cipher.init(Cipher.DECRYPT_MODE, privateKey, spec)
                cipher.doFinal(encryptedKey)
            }
        )

        var lastError: Exception? = null
        for (attempt in attempts) {
            try {
                return attempt()
            } catch (e: Exception) {
                lastError = e
                Log.w("TetherSecurity", "RSA-OAEP decrypt attempt failed: ${e.javaClass.simpleName}: ${e.message}")
            }
        }

        Log.e("TetherSecurity", "All RSA-OAEP decrypt attempts failed.")
        throw lastError ?: IllegalStateException("RSA-OAEP decrypt failed with no captured exception")
    }

    fun verifySignature(data: ByteArray, signature: ByteArray, publicKeyBytes: ByteArray): Boolean {
        return try {
            val keyFactory = KeyFactory.getInstance("RSA")
            val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(publicKeyBytes))
            val sig = Signature.getInstance("SHA256withRSA")
            sig.initVerify(publicKey)
            sig.update(data)
            val result = sig.verify(signature)
            Log.d("TetherSecurity", "Signature verification result: $result")
            result
        } catch (e: Exception) {
            Log.e("TetherSecurity", "Signature verification error: ${e.message}", e)
            false
        }
    }
}
