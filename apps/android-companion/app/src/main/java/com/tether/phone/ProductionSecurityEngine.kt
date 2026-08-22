// apps/android-companion/app/src/main/java/com/tether/phone/ProductionSecurityEngine.kt
package com.tether.phone

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

class ProductionSecurityEngine {

    companion object {
        private const val KEY_ALIAS = "TetherAsymmetricKey_v3"
        private const val STORAGE_KEY_ALIAS = "TetherStorageKey_v1"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }

    init {
        ensureKeyPairExists()
        ensureStorageKeyExists()
    }

    // PATCH: Upgraded KeyProperties digest from SHA-1 to secure SHA-256 and SHA-512
    private fun ensureKeyPairExists() {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            val kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA,
                ANDROID_KEYSTORE,
            )

            val parameterSpec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setKeySize(2048)
                .build()

            kpg.initialize(parameterSpec)
            kpg.generateKeyPair()
        }
    }

    private fun ensureStorageKeyExists() {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (!keyStore.containsAlias(STORAGE_KEY_ALIAS)) {
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
            prefs.edit().putString("pinned_windows_public_key_enc", encodedStr).apply()
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

    fun getPublicKeyBytes(): ByteArray {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val publicKey = keyStore.getCertificate(KEY_ALIAS).publicKey
        return publicKey.encoded
    }

    // PATCH: Upgraded to OAEPWithSHA-256AndMGF1Padding with SHA-1 fallback for legacy keys
    fun decryptSessionKey(encryptedKey: ByteArray): ByteArray {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val privateKeyEntry = keyStore.getEntry(KEY_ALIAS, null) as KeyStore.PrivateKeyEntry
        val privateKey = privateKeyEntry.privateKey

        return try {
            val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
            val oaepSpec = OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT
            )
            cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepSpec)
            cipher.doFinal(encryptedKey)
        } catch (_: Exception) {
            val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding")
            val oaepSpec = OAEPParameterSpec(
                "SHA-1",
                "MGF1",
                MGF1ParameterSpec.SHA1,
                PSource.PSpecified.DEFAULT
            )
            cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepSpec)
            cipher.doFinal(encryptedKey)
        }
    }

    fun computeHmac(nonce: ByteArray, sessionKey: ByteArray): ByteArray {
        val hmac = Mac.getInstance("HmacSHA256")
        val secretKey = SecretKeySpec(sessionKey, "HmacSHA256")
        hmac.init(secretKey)
        return hmac.doFinal(nonce)
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