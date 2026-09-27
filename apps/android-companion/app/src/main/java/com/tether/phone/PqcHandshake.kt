@file:Suppress("unused")

package com.tether.phone

import android.util.Log
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator
import org.bouncycastle.crypto.kems.MLKEMExtractor
import org.bouncycastle.crypto.kems.MLKEMGenerator
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters
import org.bouncycastle.crypto.params.MLDSAParameters
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters
import org.bouncycastle.crypto.params.MLKEMParameters
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters
import org.bouncycastle.crypto.signers.MLDSASigner
import java.security.SecureRandom

data class PqcKeyPair(
    val kemPublicKey: ByteArray,
    val kemPrivateKey: ByteArray,
    val dsaPublicKey: ByteArray,
    val dsaPrivateKey: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PqcKeyPair) return false
        return kemPublicKey.contentEquals(other.kemPublicKey) &&
                kemPrivateKey.contentEquals(other.kemPrivateKey) &&
                dsaPublicKey.contentEquals(other.dsaPublicKey) &&
                dsaPrivateKey.contentEquals(other.dsaPrivateKey)
    }

    override fun hashCode(): Int {
        var result = kemPublicKey.contentHashCode()
        result = (31 * result) + kemPrivateKey.contentHashCode()
        result = (31 * result) + dsaPublicKey.contentHashCode()
        result = (31 * result) + dsaPrivateKey.contentHashCode()
        return result
    }
}

/**
 * Post-Quantum Cryptographic Handshake Engine using BouncyCastle.
 * Supports ML-KEM-768 (Kyber768) for key encapsulation and ML-DSA-65 (Dilithium3) for signatures.
 */
object PqcHandshake {
    private const val TAG = "PqcHandshake"

    fun generateKeyPair(): PqcKeyPair {
        val random = SecureRandom()

        // 1. Generate ML-KEM-768 keypair
        val kemGen = MLKEMKeyPairGenerator()
        kemGen.init(MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_768))
        val kemPair = kemGen.generateKeyPair()
        val kemPub = (kemPair.public as MLKEMPublicKeyParameters).encoded
        val kemPriv = (kemPair.private as MLKEMPrivateKeyParameters).encoded

        // 2. Generate ML-DSA-65 keypair
        val dsaGen = MLDSAKeyPairGenerator()
        dsaGen.init(MLDSAKeyGenerationParameters(random, MLDSAParameters.ml_dsa_65))
        val dsaPair = dsaGen.generateKeyPair()
        val dsaPub = (dsaPair.public as MLDSAPublicKeyParameters).encoded
        val dsaPriv = (dsaPair.private as MLDSAPrivateKeyParameters).encoded

        Log.i(TAG, "Generated PQC keypair: KEM pub=${kemPub.size}B, DSA pub=${dsaPub.size}B")
        return PqcKeyPair(
            kemPublicKey = kemPub,
            kemPrivateKey = kemPriv,
            dsaPublicKey = dsaPub,
            dsaPrivateKey = dsaPriv,
        )
    }

    fun encapsulate(peerKemPubBytes: ByteArray): Pair<ByteArray, ByteArray> {
        val random = SecureRandom()
        val peerPubKeyParams = MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, peerKemPubBytes)
        val kemGen = MLKEMGenerator(random)
        val secretWithEncapsulation = kemGen.generateEncapsulated(peerPubKeyParams)
        val ciphertext = secretWithEncapsulation.encapsulation
        val sharedSecret = secretWithEncapsulation.secret
        return Pair(ciphertext, sharedSecret)
    }

    fun decapsulate(ciphertext: ByteArray, ownPrivateKeyBytes: ByteArray): ByteArray {
        val ownPrivKeyParams = MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, ownPrivateKeyBytes)
        val extractor = MLKEMExtractor(ownPrivKeyParams)
        return extractor.extractSecret(ciphertext)
    }

    fun sign(message: ByteArray, ownDsaPrivateKeyBytes: ByteArray): ByteArray {
        val ownPrivKeyParams = MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_65, ownDsaPrivateKeyBytes)
        val signer = MLDSASigner()
        signer.init(true, ownPrivKeyParams)
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    fun verify(message: ByteArray, signature: ByteArray, peerDsaPubKeyBytes: ByteArray): Boolean {
        return try {
            val peerPubKeyParams = MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, peerDsaPubKeyBytes)
            val signer = MLDSASigner()
            signer.init(false, peerPubKeyParams)
            signer.update(message, 0, message.size)
            signer.verifySignature(signature)
        } catch (e: Exception) {
            Log.e(TAG, "Failed PQC ML-DSA signature verification: ${e.message}", e)
            false
        }
    }
}
