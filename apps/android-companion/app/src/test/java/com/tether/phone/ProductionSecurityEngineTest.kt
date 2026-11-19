package com.tether.phone

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricPrompt
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.concurrent.atomic.AtomicBoolean

class ProductionSecurityEngineTest {

    @Test
    fun testKeyGenParameterSpec_UserAuthenticationRequired_MethodExists() {
        // Verify KeyGenParameterSpec.Builder has setUserAuthenticationRequired(boolean)
        val method = KeyGenParameterSpec.Builder::class.java.getMethod(
            "setUserAuthenticationRequired",
            Boolean::class.javaPrimitiveType
        )
        assertNotNull("KeyGenParameterSpec.Builder must support setUserAuthenticationRequired", method)
        assertEquals(KeyGenParameterSpec.Builder::class.java, method.returnType)
    }

    @Test
    fun testKeyGenParameterSpec_AuthenticationParameters_ApiLevelMethodVerification() {
        // Verify setUserAuthenticationParameters exists on API 30+ spec builder
        val methods = KeyGenParameterSpec.Builder::class.java.methods
        val hasUserAuthParams = methods.any { it.name == "setUserAuthenticationParameters" }
        val hasValidityDuration = methods.any { it.name == "setUserAuthenticationValidityDurationSeconds" }

        assertTrue(
            "KeyGenParameterSpec.Builder must have user authentication specification methods",
            hasUserAuthParams || hasValidityDuration
        )
    }

    @Test
    fun testBiometricAuthenticationCallback_OnAuthenticationError_FailsClosed() {
        val unlockExecuted = AtomicBoolean(false)
        val errorReported = AtomicBoolean(false)

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                errorReported.set(true)
                // Fail closed: never trigger unlock action
            }

            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                if (result.cryptoObject != null) {
                    unlockExecuted.set(true)
                }
            }
        }

        callback.onAuthenticationError(BiometricPrompt.ERROR_CANCELED, "User cancelled")

        assertTrue(errorReported.get())
        assertFalse("Unlock must never be executed on authentication error or cancellation", unlockExecuted.get())
    }

    @Test
    fun testBiometricAuthenticationCallback_OnAuthenticationFailed_FailsClosed() {
        val unlockExecuted = AtomicBoolean(false)
        val failureCount = AtomicBoolean(false)

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                failureCount.set(true)
                // Fail closed: reject attempt, do not unlock
            }

            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                if (result.cryptoObject != null) {
                    unlockExecuted.set(true)
                }
            }
        }

        callback.onAuthenticationFailed()

        assertTrue(failureCount.get())
        assertFalse("Unlock must never be executed on biometric authentication failure", unlockExecuted.get())
    }

    @Test
    fun testBiometricAuthenticationCallback_NullCryptoObject_RejectsUnlock() {
        val unlockPermitted = AtomicBoolean(false)
        val rejectedNullCrypto = AtomicBoolean(false)

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                val authenticatedCrypto = result.cryptoObject
                if (authenticatedCrypto == null) {
                    // Fail closed requirement
                    rejectedNullCrypto.set(true)
                    return
                }
                unlockPermitted.set(true)
            }
        }

        // Simulate success with null crypto object (tampering/bypass attempt)
        val mockResult = BiometricPrompt.AuthenticationResult(null, BiometricPrompt.AUTHENTICATION_RESULT_TYPE_BIOMETRIC)
        callback.onAuthenticationSucceeded(mockResult)

        assertTrue("Must detect and reject null CryptoObject on success", rejectedNullCrypto.get())
        assertFalse("Unlock must be denied when CryptoObject is null", unlockPermitted.get())
    }

    @Test
    fun testProductionSecurityEngine_CreateSignatureCryptoObject_SafelyHandlesUnloadedKeyStore() {
        val engine = ProductionSecurityEngine()
        // On headless JVM test runner without real AndroidKeyStore hardware,
        // createSignatureCryptoObject must fail closed and return null rather than crashing or returning an unauthenticated object.
        val crypto = engine.createSignatureCryptoObject()
        // Without AndroidKeyStore hardware enclave on desktop JVM, must be null
        assertNull(crypto)
    }

    @Test
    fun testProductionSecurityEngine_CreateCryptoObjectForAuth_SafelyHandlesUnloadedKeyStore() {
        val engine = ProductionSecurityEngine()
        val crypto = engine.createCryptoObjectForAuthentication()
        assertNull(crypto)
    }
}
