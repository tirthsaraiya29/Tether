package com.tether.phone

import android.content.Context
import android.os.Build
import android.util.Base64
import android.util.Log
import org.json.JSONObject
import java.nio.charset.StandardCharsets

sealed class PairingResult {
    data class Authenticated(val peerDeviceId: String, val peerFingerprint: String) : PairingResult()
    data class PairingRequired(val peerDeviceId: String, val peerFingerprint: String, val peerName: String) : PairingResult()
    data class PairingDenied(val reason: String) : PairingResult()
    data class KeyMismatch(val presentedFingerprint: String, val pinnedFingerprint: String) : PairingResult()
    data class Error(val message: String) : PairingResult()
}

class TetherPairingManager(
    private val context: Context,
    private val securityEngine: ProductionSecurityEngine
) {

    companion object {
        private const val TAG = "TetherPairingManager"
        const val PROTOCOL_VERSION = "1.0"
    }

    fun executeHandshake(
        transport: TetherTransport,
        isUserInitiatedPairing: Boolean = false
    ): PairingResult {
        try {
            val phonePubKeyBytes = securityEngine.getPublicKeyBytes()
            val phoneFingerprint = securityEngine.computePublicKeyFingerprint(phonePubKeyBytes)
            val phonePubKeyBase64 = Base64.encodeToString(phonePubKeyBytes, Base64.NO_WRAP)

            val pinnedKeyBytes = securityEngine.getPinnedKeyDecrypted(context)
            val pinnedFingerprint = securityEngine.computePublicKeyFingerprint(pinnedKeyBytes)

            val isAlreadyPinned = (pinnedKeyBytes != null && pinnedKeyBytes.isNotEmpty())

            // 1. Construct HANDSHAKE_INIT payload
            val initJson = JSONObject().apply {
                put("type", "HANDSHAKE_INIT")
                put("version", PROTOCOL_VERSION)
                put("deviceId", phoneFingerprint)
                put("deviceName", Build.MODEL)
                put("publicKey", phonePubKeyBase64)
                put("isPairingRequested", isUserInitiatedPairing || !isAlreadyPinned)
                put("capabilities", "CLIPBOARD,FILES,NOTIFICATIONS,MEDIA,TERMINAL,POWER_ELEVATED")
            }

            Log.i(TAG, "Sending HANDSHAKE_INIT over TLS 1.3 (isPairingRequested=${isUserInitiatedPairing || !isAlreadyPinned})...")
            transport.sendFrame(initJson.toString().toByteArray(StandardCharsets.UTF_8))

            // 2. Read HANDSHAKE_RESPONSE payload
            val respBytes = transport.readFrame() ?: return PairingResult.Error("No response from Windows host")
            val respJson = JSONObject(String(respBytes, StandardCharsets.UTF_8))

            val type = respJson.optString("type")
            if (type != "HANDSHAKE_RESPONSE") {
                return PairingResult.Error("Invalid handshake response type: $type")
            }

            val winDeviceId = respJson.optString("deviceId", "UNKNOWN_WIN")
            val winName = respJson.optString("deviceName", "Windows PC")
            val winPubKeyBase64 = respJson.optString("publicKey", "")
            val pairingStatus = respJson.optString("status", "UNPAIRED")

            if (winPubKeyBase64.isBlank()) {
                return PairingResult.Error("Windows host returned empty public key")
            }

            val winPubKeyBytes = Base64.decode(winPubKeyBase64, Base64.NO_WRAP)
            val winFingerprint = securityEngine.computePublicKeyFingerprint(winPubKeyBytes)

            Log.i(TAG, "Received HANDSHAKE_RESPONSE from $winName ($winDeviceId), FP=$winFingerprint, status=$pairingStatus")

            // 3. Verify against pinned key if previously paired
            if (isAlreadyPinned) {
                if (!winPubKeyBytes.contentEquals(pinnedKeyBytes)) {
                    Log.e(TAG, "SECURITY ALERT: Windows identity key mismatch! Presented: $winFingerprint, Pinned: $pinnedFingerprint")
                    return PairingResult.KeyMismatch(
                        presentedFingerprint = winFingerprint,
                        pinnedFingerprint = pinnedFingerprint
                    )
                }
                Log.i(TAG, "Cryptographic identity verified against pinned Windows public key!")
                return PairingResult.Authenticated(
                    peerDeviceId = winDeviceId,
                    peerFingerprint = winFingerprint
                )
            }

            // 4. Handle TOFU First Pairing
            if (pairingStatus == "PAIRING_ACCEPTED" || pairingStatus == "PAIRED") {
                Log.i(TAG, "First pairing approved by Windows Desktop UI. Pinning identity key...")
                securityEngine.storePinnedKeySecurely(context, winPubKeyBytes)
                return PairingResult.Authenticated(
                    peerDeviceId = winDeviceId,
                    peerFingerprint = winFingerprint
                )
            } else if (pairingStatus == "PAIRING_DENIED") {
                Log.w(TAG, "First pairing was rejected by Windows user.")
                return PairingResult.PairingDenied("Pairing request rejected on Windows PC")
            } else {
                Log.i(TAG, "Windows host requires explicit pairing approval from Desktop UI.")
                return PairingResult.PairingRequired(
                    peerDeviceId = winDeviceId,
                    peerFingerprint = winFingerprint,
                    peerName = winName
                )
            }

        } catch (e: Exception) {
            Log.e(TAG, "Handshake execution error: ${e.message}", e)
            return PairingResult.Error("Handshake error: ${e.message}")
        }
    }
}
