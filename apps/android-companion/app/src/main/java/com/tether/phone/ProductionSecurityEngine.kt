package com.tether.phone

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

class ProductionSecurityEngine {

    companion object {
        private const val KEY_ALIAS = "TetherAsymmetricKey_v3"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }

    init {
        ensureKeyPairExists()
    }

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
                // Both digests enabled to support cross-platform handshake variations
                // and precise alignment with standard desktop framework implementations
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA1)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setKeySize(2048)
                .build()

            kpg.initialize(parameterSpec)
            kpg.generateKeyPair()
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

        // Pure OAEP SHA-1 matching standard .NET Windows client RSAEncryptionPadding.OaepSHA1
        // Satisfies hardware keystore constraints seamlessly across all Android implementations
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding")
        val oaepSpec = OAEPParameterSpec(
            "SHA-1",
            "MGF1",
            MGF1ParameterSpec.SHA1,
            PSource.PSpecified.DEFAULT
        )

        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepSpec)
        return cipher.doFinal(encryptedKey)
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
            android.util.Log.d("TetherSecurity", "Signature verification result: $result")
            result
        } catch (e: Exception) {
            android.util.Log.e("TetherSecurity", "Signature verification error: ${e.message}", e)
            false
        }
    }
}