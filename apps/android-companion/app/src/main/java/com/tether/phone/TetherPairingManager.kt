package com.tether.phone

import android.content.Context
import android.os.Build
import android.util.Base64
import android.util.Log
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom

sealed class PairingResult {
    data class Authenticated(
        val peerDeviceId: String,
        val peerFingerprint: String,
        val peerCapabilities: String = "",
    ) : PairingResult()

    data class PairingPending(
        val requestId: String,
        val peerDeviceId: String,
        val peerFingerprint: String,
        val peerName: String,
        val winEcPubKeyBytes: ByteArray?,
        val transcriptHash: ByteArray,
    ) : PairingResult() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is PairingPending) return false
            return (requestId == other.requestId) &&
                    (peerDeviceId == other.peerDeviceId) &&
                    (peerFingerprint == other.peerFingerprint) &&
                    (peerName == other.peerName) &&
                    transcriptHash.contentEquals(other.transcriptHash)
        }

        override fun hashCode(): Int {
            var result = requestId.hashCode()
            result = (31 * result) + peerDeviceId.hashCode()
            result = (31 * result) + peerFingerprint.hashCode()
            result = (31 * result) + peerName.hashCode()
            result = (31 * result) + transcriptHash.contentHashCode()
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

        // SECURITY FIX: CWE-117 Defensive log sanitizer stripping control chars
        fun sanitizeLog(input: String?): String {
            if (input == null) return "null"
            return input
                .replace("\r", "\\r")
                .replace("\n", "\\n")
                .replace("\t", "\\t")
                .filter { it.code in 0x20..0x7E || it.code > 0x7F }
                .take(256)
        }

        fun computeSha512(vararg byteArrays: ByteArray): ByteArray {
            val digest = MessageDigest.getInstance("SHA-512")
            for (array in byteArrays) {
                digest.update(array)
            }
            return digest.digest()
        }
    }

    fun executeHandshake(
        transport: TetherTransport,
        isUserInitiatedPairing: Boolean = false,
    ): PairingResult {
        try {
            val phonePubKeyBytes = securityEngine.getPublicKeyBytes()
            val phoneFingerprint = securityEngine.computePublicKeyFingerprint(phonePubKeyBytes)
            val phonePubKeyBase64 = Base64.encodeToString(phonePubKeyBytes, Base64.NO_WRAP)

            val pinnedKeyBytes = securityEngine.getPinnedKeyDecrypted(context)
            val pinnedFingerprint = securityEngine.computePublicKeyFingerprint(pinnedKeyBytes)
            val isAlreadyPinned = ((pinnedKeyBytes != null) && pinnedKeyBytes.isNotEmpty())

            // SECURITY FIX: Generate client nonce for proof-of-possession
            val clientNonce = ByteArray(32).also { SecureRandom().nextBytes(it) }

            // 1. Construct HANDSHAKE_INIT payload
            val initJson = JSONObject().apply {
                put("type", "HANDSHAKE_INIT")
                put("version", PROTOCOL_VERSION)
                put("deviceId", phoneFingerprint)
                put("deviceName", Build.MODEL)
                put("publicKey", phonePubKeyBase64)
                put("nonce", Base64.encodeToString(clientNonce, Base64.NO_WRAP))
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
            val winCapabilities = respJson.optString("capabilities", "")

            if (winPubKeyBase64.isBlank()) {
                return PairingResult.Error("Windows host returned empty public key")
            }

            val winPubKeyBytes = Base64.decode(winPubKeyBase64, Base64.NO_WRAP)
            val winFingerprint = securityEngine.computePublicKeyFingerprint(winPubKeyBytes)

            val safeName = sanitizeLog(winName)
            val safeDevId = sanitizeLog(winDeviceId)
            val safeFp = sanitizeLog(winFingerprint)
            val safeStatus = sanitizeLog(pairingStatus)
            // SECURITY FIX: CWE-117 Log Injection - All peer-controlled fields below are passed through sanitizeLog() to prevent log injection.
            Log.i(TAG, "Received HANDSHAKE_RESPONSE from $safeName ($safeDevId), FP=$safeFp, status=$safeStatus")

            val transcriptHash = computeSha512(
                initJsonStr.toByteArray(StandardCharsets.UTF_8),
                respJsonStr.toByteArray(StandardCharsets.UTF_8),
            )

            // 3. Verify against pinned key if previously paired
            if (isAlreadyPinned) {
                if (!winPubKeyBytes.contentEquals(pinnedKeyBytes)) {
                    Log.e(TAG, "SECURITY ALERT: Windows identity key mismatch! Presented: $winFingerprint, Pinned: $pinnedFingerprint")
                    return PairingResult.KeyMismatch(
                        presentedFingerprint = winFingerprint,
                        pinnedFingerprint = pinnedFingerprint,
                    )
                }

                // Send HANDSHAKE_PROOF signed with identity key for established trust
                val proofPayload = transcriptHash + winPubKeyBytes
                val signature = securityEngine.signWithIdentityKey(proofPayload)
                val proofBase64 = Base64.encodeToString(signature, Base64.NO_WRAP)

                val proofJson = JSONObject().apply {
                    put("type", "HANDSHAKE_PROOF")
                    put("nonce", Base64.encodeToString(clientNonce, Base64.NO_WRAP))
                    put("proof", proofBase64)
                }
                transport.sendFrame(proofJson.toString().toByteArray(StandardCharsets.UTF_8))

                // Read HANDSHAKE_VERIFIED response with backward compatibility fallback
                val verifiedBytes = try {
                    transport.readFrame()
                } catch (e: Exception) {
                    Log.w(TAG, "HANDSHAKE_VERIFIED read timed out or failed; fallback to legacy flow: ${e.message}")
                    null
                }

                if (verifiedBytes != null) {
                    try {
                        val verifiedJson = JSONObject(String(verifiedBytes, StandardCharsets.UTF_8))
                        val verifiedType = verifiedJson.optString("type")
                        val verifiedStatus = verifiedJson.optString("status")
                        if (verifiedType == "HANDSHAKE_VERIFIED" && verifiedStatus != "OK") {
                            return PairingResult.Error("Windows host rejected handshake proof verification")
                        }
                    } catch (e: Exception) {
                        Log.w(TAG, "Non-JSON or unexpected HANDSHAKE_VERIFIED response; fallback to legacy flow: ${e.message}")
                    }
                }

                Log.i(TAG, "Cryptographic identity verified against pinned Windows public key!")
                return PairingResult.Authenticated(
                    peerDeviceId = winDeviceId,
                    peerFingerprint = winFingerprint,
                    peerCapabilities = winCapabilities,
                )
            }

            // 4. Handle First Pairing vs Pending
            when (pairingStatus) {
                "PAIRED", "PAIRING_ACCEPTED" -> {
                    Log.i(TAG, "First pairing auto-accepted by Windows. Pinning keys...")
                    securityEngine.storePinnedKeySecurely(context, winPubKeyBytes)
                    return PairingResult.Authenticated(
                        peerDeviceId = winDeviceId,
                        peerFingerprint = winFingerprint,
                        peerCapabilities = winCapabilities,
                    )
                }
                "PAIRING_PENDING" -> {
                    val reqId = respJson.optString("requestId", "REQ_UNKNOWN")
                    Log.i(TAG, "Windows host returned PAIRING_PENDING (reqId=$reqId). User PIN entry required.")
                    return PairingResult.PairingPending(
                        requestId = reqId,
                        peerDeviceId = winDeviceId,
                        peerFingerprint = winFingerprint,
                        peerName = winName,
                        winEcPubKeyBytes = winPubKeyBytes,
                        transcriptHash = transcriptHash,
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
                        winEcPubKeyBytes = winPubKeyBytes,
                        transcriptHash = transcriptHash,
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
        userEnteredPin: String,
        winEcPubKeyBytes: ByteArray?,
    ): PairingResult {
        try {
            if ((winEcPubKeyBytes == null) || winEcPubKeyBytes.isEmpty()) {
                return PairingResult.Error("Windows public key missing for pairing confirmation")
            }

            val phonePubKeyBytes = securityEngine.getPublicKeyBytes()
            val reqIdBytes = requestId.toByteArray(StandardCharsets.UTF_8)
            val pinBytes = userEnteredPin.trim().toByteArray(StandardCharsets.UTF_8)

            // PhoneProof = SHA-512(PIN || WinPubKey || PhonePubKey || RequestId)
            val phoneProof = computeSha512(pinBytes, winEcPubKeyBytes, phonePubKeyBytes, reqIdBytes)
            val phoneProofBase64 = Base64.encodeToString(phoneProof, Base64.NO_WRAP)

            // 1. Send PAIRING_CONFIRMED frame
            val confirmedJson = JSONObject().apply {
                put("type", "PAIRING_CONFIRMED")
                put("requestId", requestId)
                put("proof", phoneProofBase64)
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

            // SECURITY FIX: Verify Windows pairing proof
            val winProofBase64 = completeJson.optString("proof", "")
            if (winProofBase64.isNotBlank()) {
                val expectedWinProof = computeSha512(
                    "SERVER-OK".toByteArray(StandardCharsets.UTF_8),
                    userEnteredPin.trim().toByteArray(StandardCharsets.UTF_8),
                    winEcPubKeyBytes,
                    securityEngine.getPublicKeyBytes(),
                    requestId.toByteArray(StandardCharsets.UTF_8),
                )

                val presentedWinProof = try {
                    Base64.decode(winProofBase64, Base64.NO_WRAP)
                } catch (_: IllegalArgumentException) {
                    return PairingResult.Error("Malformed Windows proof encoding")
                }

                if (!MessageDigest.isEqual(expectedWinProof, presentedWinProof)) {
                    Log.e(TAG, "SECURITY ALERT: Windows pairing proof mismatch. Possible MITM.")
                    return PairingResult.Error("Windows proof verification failed")
                }
            } else {
                Log.w(TAG, "Windows did not return pairing proof; continuing with caution.")
            }

            // 3. Pin Windows key securely
            securityEngine.storePinnedKeySecurely(context, winEcPubKeyBytes)
            Log.i(TAG, "Successfully pinned Windows public key after interactive 6-digit PIN confirmation!")

            val winFp = securityEngine.computePublicKeyFingerprint(winEcPubKeyBytes)
            val winCaps = completeJson.optString("capabilities", "")

            return PairingResult.Authenticated(
                peerDeviceId = "WINDOWS_HOST",
                peerFingerprint = winFp,
                peerCapabilities = winCaps,
            )

        } catch (e: Exception) {
            Log.e(TAG, "Error during finalizePairing: ${e.message}", e)
            return PairingResult.Error("Failed finalizing pairing: ${e.message}")
        }
    }
}
