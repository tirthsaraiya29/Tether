package com.tether.phone

import android.content.Context
import android.os.Build
import android.util.Base64
import android.util.Log
import org.json.JSONObject
import java.nio.charset.StandardCharsets

sealed class PairingResult {
    data class Authenticated(val peerDeviceId: String, val peerFingerprint: String) : PairingResult()
    data class PairingPending(
        val requestId: String,
        val peerDeviceId: String,
        val peerFingerprint: String,
        val peerName: String,
        val sasCode: String,
        val winDsaPubKeyBytes: ByteArray?,
        val winEcPubKeyBytes: ByteArray?,
    ) : PairingResult() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is PairingPending) return false
            return (requestId == other.requestId) &&
                    (peerDeviceId == other.peerDeviceId) &&
                    (peerFingerprint == other.peerFingerprint) &&
                    (peerName == other.peerName) &&
                    (sasCode == other.sasCode)
        }

        override fun hashCode(): Int {
            var result = requestId.hashCode()
            result = (31 * result) + peerDeviceId.hashCode()
            result = (31 * result) + peerFingerprint.hashCode()
            result = (31 * result) + peerName.hashCode()
            result = (31 * result) + sasCode.hashCode()
            return result
        }
    }

    data class PairingDenied(val reason: String) : PairingResult()
    data class KeyMismatch(val presentedFingerprint: String, val pinnedFingerprint: String) : PairingResult()
    data class Error(val message: String) : PairingResult()
}

class TetherPairingManager(
    private val context: Context,
    private val securityEngine: ProductionSecurityEngine,
) {

    companion object {
        private const val TAG = "TetherPairingManager"
        const val PROTOCOL_VERSION = "2.0"
    }

    fun executeHandshake(
        transport: TetherTransport,
        isUserInitiatedPairing: Boolean = false,
    ): PairingResult {
        try {
            val phonePubKeyBytes = securityEngine.getPublicKeyBytes()
            val phoneFingerprint = securityEngine.computePublicKeyFingerprint(phonePubKeyBytes)
            val phonePubKeyBase64 = Base64.encodeToString(phonePubKeyBytes, Base64.NO_WRAP)

            val phoneKemPub = securityEngine.getPqcKemPublicKeyBytes(context)
            val phoneDsaPub = securityEngine.getPqcDsaPublicKeyBytes(context)
            val phoneKemPubBase64 = Base64.encodeToString(phoneKemPub, Base64.NO_WRAP)
            val phoneDsaPubBase64 = Base64.encodeToString(phoneDsaPub, Base64.NO_WRAP)

            val pqcKeyPair = securityEngine.getOrCreatePqcKeyPair(context)

            val pinnedKeyBytes = securityEngine.getPinnedKeyDecrypted(context)
            val pinnedFingerprint = securityEngine.computePublicKeyFingerprint(pinnedKeyBytes)
            val pinnedPqcKeys = securityEngine.getPinnedWindowsPqcKeys(context)

            val isAlreadyPinned = ((pinnedKeyBytes != null) && pinnedKeyBytes.isNotEmpty())

            // 1. Construct HANDSHAKE_INIT payload
            val initJson = JSONObject().apply {
                put("type", "HANDSHAKE_INIT")
                put("version", PROTOCOL_VERSION)
                put("deviceId", phoneFingerprint)
                put("deviceName", Build.MODEL)
                put("publicKey", phonePubKeyBase64)
                put("pqcCapabilities", "ML-KEM-768,ML-DSA-65")
                put("pqcKemPublicKey", phoneKemPubBase64)
                put("pqcDsaPublicKey", phoneDsaPubBase64)
                put("isPairingRequested", isUserInitiatedPairing || !isAlreadyPinned)
                put("capabilities", "CLIPBOARD,FILES,NOTIFICATIONS,MEDIA,TERMINAL,POWER_ELEVATED")
            }

            val initJsonStr = initJson.toString()
            Log.i(TAG, "Sending HANDSHAKE_INIT v2.0 over TLS 1.3 (isPairingRequested=${isUserInitiatedPairing || !isAlreadyPinned})...")
            transport.sendFrame(initJsonStr.toByteArray(StandardCharsets.UTF_8))

            // 2. Read HANDSHAKE_RESPONSE payload
            val respBytes = transport.readFrame() ?: return PairingResult.Error("No response from Windows host")
            val respJsonStr = String(respBytes, StandardCharsets.UTF_8)
            val respJson = JSONObject(respJsonStr)

            val type = respJson.optString("type")
            if (type != "HANDSHAKE_RESPONSE") {
                return PairingResult.Error("Invalid handshake response type: $type")
            }

            val winDeviceId = respJson.optString("deviceId", "UNKNOWN_WIN")
            val winName = respJson.optString("deviceName", "Windows PC")
            val winPubKeyBase64 = respJson.optString("publicKey", "")
            val pairingStatus = respJson.optString("status", "UNPAIRED")
            val pqcSupported = respJson.optBoolean("pqcSupported", true)
            val pqcEncapsulationBase64 = respJson.optString("pqcEncapsulation", "")
            val winDsaPubKeyBase64 = respJson.optString("pqcDsaPublicKey", "")

            if (winPubKeyBase64.isBlank()) {
                return PairingResult.Error("Windows host returned empty public key")
            }

            val winPubKeyBytes = Base64.decode(winPubKeyBase64, Base64.NO_WRAP)
            val winFingerprint = securityEngine.computePublicKeyFingerprint(winPubKeyBytes)
            val winDsaPubKeyBytes = if (winDsaPubKeyBase64.isNotBlank()) Base64.decode(winDsaPubKeyBase64, Base64.NO_WRAP) else null

            Log.i(TAG, "Received HANDSHAKE_RESPONSE from $winName ($winDeviceId), FP=$winFingerprint, status=$pairingStatus, PQC=$pqcSupported")

            // Derive PQC Session Cipher if available
            var sasCode = "000000"
            if (pqcSupported && pqcEncapsulationBase64.isNotBlank()) {
                try {
                    val ciphertext = Base64.decode(pqcEncapsulationBase64, Base64.NO_WRAP)
                    val sharedSecret = PqcHandshake.decapsulate(ciphertext, pqcKeyPair.kemPrivateKey)
                    val transcriptHash = SessionCipher.computeTranscriptHash(initJsonStr, respJsonStr)
                    val sessionCipher = SessionCipher.derive(sharedSecret, transcriptHash)
                    sasCode = respJson.optString("sasCode", SessionCipher.computeSasCode(transcriptHash))

                    // Attach session cipher to transport for subsequent frames
                    transport.attachSessionCipher(sessionCipher)
                    Log.i(TAG, "PQC ML-KEM-768 session cipher successfully established! SAS=$sasCode")
                } catch (e: Exception) {
                    Log.e(TAG, "Failed PQC session cipher derivation: ${e.message}", e)
                }
            }

            // 3. Verify against pinned key if previously paired
            if (isAlreadyPinned) {
                if (!winPubKeyBytes.contentEquals(pinnedKeyBytes)) {
                    Log.e(TAG, "SECURITY ALERT: Windows identity key mismatch! Presented: $winFingerprint, Pinned: $pinnedFingerprint")
                    return PairingResult.KeyMismatch(
                        presentedFingerprint = winFingerprint,
                        pinnedFingerprint = pinnedFingerprint,
                    )
                }

                // Downgrade protection rule: If pinned record had PQC enabled, refuse non-PQC connections
                if ((pinnedPqcKeys != null) && !pqcSupported) {
                    Log.e(TAG, "SECURITY ALERT: PQC downgrade attack detected! Pinned record required PQC.")
                    return PairingResult.KeyMismatch(
                        presentedFingerprint = "$winFingerprint (PQC Disabled)",
                        pinnedFingerprint = "$pinnedFingerprint (PQC Required)",
                    )
                }

                Log.i(TAG, "Cryptographic identity verified against pinned Windows public key!")
                return PairingResult.Authenticated(
                    peerDeviceId = winDeviceId,
                    peerFingerprint = winFingerprint,
                )
            }

            // 4. Handle First Pairing vs Pending
            when (pairingStatus) {
                "PAIRED", "PAIRING_ACCEPTED" -> {
                    Log.i(TAG, "First pairing auto-accepted by Windows. Pinning keys...")
                    securityEngine.storePinnedKeySecurely(context, winPubKeyBytes)
                    winDsaPubKeyBytes?.let {
                        securityEngine.storePinnedWindowsPqcKeys(context, winPubKeyBytes, it)
                    }
                    return PairingResult.Authenticated(
                        peerDeviceId = winDeviceId,
                        peerFingerprint = winFingerprint,
                    )
                }
                "PAIRING_PENDING" -> {
                    val reqId = respJson.optString("requestId", "REQ_UNKNOWN")
                    Log.i(TAG, "Windows host returned PAIRING_PENDING (reqId=$reqId). SAS=$sasCode")
                    return PairingResult.PairingPending(
                        requestId = reqId,
                        peerDeviceId = winDeviceId,
                        peerFingerprint = winFingerprint,
                        peerName = winName,
                        sasCode = sasCode,
                        winDsaPubKeyBytes = winDsaPubKeyBytes,
                        winEcPubKeyBytes = winPubKeyBytes,
                    )
                }
                "PAIRING_DENIED" -> {
                    Log.w(TAG, "Pairing request rejected by Windows host.")
                    return PairingResult.PairingDenied("Pairing request rejected on Windows PC")
                }
                else -> {
                    val reqId = respJson.optString("requestId", "REQ_UNKNOWN")
                    return PairingResult.PairingPending(
                        requestId = reqId,
                        peerDeviceId = winDeviceId,
                        peerFingerprint = winFingerprint,
                        peerName = winName,
                        sasCode = sasCode,
                        winDsaPubKeyBytes = winDsaPubKeyBytes,
                        winEcPubKeyBytes = winPubKeyBytes,
                    )
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Handshake execution error: ${e.message}", e)
            return PairingResult.Error("Handshake error: ${e.message}")
        }
    }

    fun finalizePairing(
        transport: TetherTransport,
        requestId: String,
        winEcPubKeyBytes: ByteArray?,
        winDsaPubKeyBytes: ByteArray?,
    ): PairingResult {
        try {
            val pqcKeyPair = securityEngine.getOrCreatePqcKeyPair(context)

            // 1. Send PAIRING_CONFIRMED frame
            val confirmedJson = JSONObject().apply {
                put("type", "PAIRING_CONFIRMED")
                put("requestId", requestId)
                put("phoneDsaPublicKey", Base64.encodeToString(pqcKeyPair.dsaPublicKey, Base64.NO_WRAP))
            }
            Log.i(TAG, "Sending PAIRING_CONFIRMED frame for requestId=$requestId...")
            transport.sendFrame(confirmedJson.toString().toByteArray(StandardCharsets.UTF_8))

            // 2. Read PAIRING_COMPLETE frame
            val completeBytes = transport.readFrame() ?: return PairingResult.Error("No PAIRING_COMPLETE response from Windows")
            val completeJson = JSONObject(String(completeBytes, StandardCharsets.UTF_8))
            val status = completeJson.optString("status", "OK")

            if ((status != "OK") && (status != "PAIRING_COMPLETE")) {
                return PairingResult.Error("Pairing complete failed with status: $status")
            }

            // 3. Pin Windows keys securely
            if ((winEcPubKeyBytes != null) && winEcPubKeyBytes.isNotEmpty()) {
                securityEngine.storePinnedKeySecurely(context, winEcPubKeyBytes)
                if ((winDsaPubKeyBytes != null) && winDsaPubKeyBytes.isNotEmpty()) {
                    securityEngine.storePinnedWindowsPqcKeys(context, winEcPubKeyBytes, winDsaPubKeyBytes)
                }
                Log.i(TAG, "Successfully pinned Windows classical and PQC keys after interactive confirmation!")
            }

            // 4. Send SESSION_READY frame
            val sessionReadyJson = JSONObject().apply {
                put("type", "SESSION_READY")
            }
            Log.i(TAG, "Sending SESSION_READY frame to transition host to command loop...")
            transport.sendFrame(sessionReadyJson.toString().toByteArray(StandardCharsets.UTF_8))

            val winFp = if (winEcPubKeyBytes != null) securityEngine.computePublicKeyFingerprint(winEcPubKeyBytes) else "PINNED"
            return PairingResult.Authenticated(
                peerDeviceId = "WINDOWS_HOST",
                peerFingerprint = winFp,
            )

        } catch (e: Exception) {
            Log.e(TAG, "Error during finalizePairing: ${e.message}", e)
            return PairingResult.Error("Failed finalizing pairing: ${e.message}")
        }
    }
}
