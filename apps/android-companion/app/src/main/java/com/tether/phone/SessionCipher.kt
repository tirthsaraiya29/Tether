@file:Suppress("unused")

package com.tether.phone

import android.util.Base64
import android.util.Log
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.abs

/**
 * Provides AES-256-GCM frame-level encryption and decryption for PQC-secured Tether sessions.
 * Derived using HKDF-SHA256 from the ML-KEM shared secret and handshake transcript hash.
 */
class SessionCipher private constructor(
    private val key: SecretKey,
) {
    companion object {
        private const val TAG = "SessionCipher"
        private const val INFO_LABEL = "tether-frame-key-v2"
        private const val NONCE_SIZE_BYTES = 12
        private const val TAG_SIZE_BITS = 128
        private const val KEY_SIZE_BYTES = 32

        fun derive(mlkemSharedSecret: ByteArray, transcriptHash: ByteArray): SessionCipher {
            val ikm = ByteArray(mlkemSharedSecret.size + transcriptHash.size)
            System.arraycopy(mlkemSharedSecret, 0, ikm, 0, mlkemSharedSecret.size)
            System.arraycopy(transcriptHash, 0, ikm, mlkemSharedSecret.size, transcriptHash.size)

            val derivedKeyBytes = hkdfSha256(
                salt = ByteArray(KEY_SIZE_BYTES),
                ikm = ikm,
                info = INFO_LABEL.toByteArray(StandardCharsets.UTF_8),
            )

            val secretKey = SecretKeySpec(derivedKeyBytes, "AES")
            return SessionCipher(secretKey)
        }

        private fun hkdfSha256(salt: ByteArray, ikm: ByteArray, info: ByteArray): ByteArray {
            // HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
            val mac = Mac.getInstance("HmacSHA256")
            val actualSalt = if (salt.isEmpty()) ByteArray(32) else salt
            mac.init(SecretKeySpec(actualSalt, "HmacSHA256"))
            val prk = mac.doFinal(ikm)

            // HKDF-Expand: OKM = HMAC-Hash(PRK, info | 0x01)
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            val expandInput = ByteArray(info.size + 1)
            System.arraycopy(info, 0, expandInput, 0, info.size)
            expandInput[info.size] = 0x01.toByte()

            val okm = mac.doFinal(expandInput)
            return okm.copyOf(KEY_SIZE_BYTES)
        }

        fun computeTranscriptHash(initJsonStr: String, responseJsonStr: String): ByteArray {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(initJsonStr.toByteArray(StandardCharsets.UTF_8))
            digest.update(responseJsonStr.toByteArray(StandardCharsets.UTF_8))
            return digest.digest()
        }

        fun computeSasCode(transcriptHash: ByteArray): String {
            if (transcriptHash.size < 4) return "000000"
            val num = ((transcriptHash[0].toInt() and 0xFF) shl 24) or
                    ((transcriptHash[1].toInt() and 0xFF) shl 16) or
                    ((transcriptHash[2].toInt() and 0xFF) shl 8) or
                    (transcriptHash[3].toInt() and 0xFF)
            val sasVal = abs(num) % 1_000_000
            return String.format(Locale.US, "%06d", sasVal)
        }
    }

    fun encrypt(plaintext: ByteArray): ByteArray {
        val nonce = ByteArray(NONCE_SIZE_BYTES)
        SecureRandom().nextBytes(nonce)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(TAG_SIZE_BITS, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, key, spec)

        val combined = cipher.doFinal(plaintext)
        val ciphertextLen = combined.size - 16
        val ciphertextBytes = combined.copyOfRange(0, ciphertextLen)
        val tagBytes = combined.copyOfRange(ciphertextLen, combined.size)

        val envelopeJson = JSONObject().apply {
            put("type", "ENCRYPTED_FRAME")
            put("nonce", Base64.encodeToString(nonce, Base64.NO_WRAP))
            put("ciphertext", Base64.encodeToString(ciphertextBytes, Base64.NO_WRAP))
            put("tag", Base64.encodeToString(tagBytes, Base64.NO_WRAP))
        }

        return envelopeJson.toString().toByteArray(StandardCharsets.UTF_8)
    }

    fun decrypt(envelopeBytes: ByteArray): ByteArray {
        val envelopeStr = String(envelopeBytes, StandardCharsets.UTF_8)
        if (!envelopeStr.trim().startsWith("{") || !envelopeStr.contains("\"ENCRYPTED_FRAME\"")) {
            // Fallback for unencrypted control frames during transition
            return envelopeBytes
        }

        try {
            val json = JSONObject(envelopeStr)
            val nonceBase64 = json.getString("nonce")
            val ciphertextBase64 = json.getString("ciphertext")
            val tagBase64 = json.optString("tag", "")

            val nonce = Base64.decode(nonceBase64, Base64.NO_WRAP)
            val ciphertext = Base64.decode(ciphertextBase64, Base64.NO_WRAP)
            val tag = if (tagBase64.isNotBlank()) Base64.decode(tagBase64, Base64.NO_WRAP) else ByteArray(0)

            val combined = ByteArray(ciphertext.size + tag.size)
            System.arraycopy(ciphertext, 0, combined, 0, ciphertext.size)
            if (tag.isNotEmpty()) {
                System.arraycopy(tag, 0, combined, ciphertext.size, tag.size)
            }

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val spec = GCMParameterSpec(TAG_SIZE_BITS, nonce)
            cipher.init(Cipher.DECRYPT_MODE, key, spec)

            return cipher.doFinal(combined)
        } catch (e: Exception) {
            val safeErr = e.message?.replace("\r", "\\r")?.replace("\n", "\\n")?.take(256) ?: "null"
            Log.e(TAG, "Failed to decrypt frame: $safeErr", e)
            throw IllegalStateException("Frame decryption error: $safeErr", e)
        }
    }
}
