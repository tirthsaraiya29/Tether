package com.tether.phone

import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.fragment.app.FragmentActivity
import com.tether.phone.ui.components.DeepSpaceCanvasVisualizer
import com.tether.phone.ui.components.ProfessionalGlassSurface
import com.tether.phone.ui.components.TacticalAction
import com.tether.phone.ui.theme.AlertRed
import com.tether.phone.ui.theme.LiquidCyan
import com.tether.phone.ui.theme.TetherTheme
import com.tether.phone.ui.theme.TextPrimary
import com.tether.phone.ui.theme.TextSecondary

class PowerEventActivity : FragmentActivity() {

    companion object {
        const val TAG = "PowerEventActivity"
        const val EXTRA_POWER_EVENT_TYPE = "eventType"
        const val EXTRA_POWER_EVENT_TIMESTAMP = "eventTimestamp"
    }

    private var eventType: String = "LOCK"
    private var eventTimestamp: Long = 0L

    @Suppress("DEPRECATION")
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        window.addFlags(
            android.view.WindowManager.LayoutParams.FLAG_SECURE or
            android.view.WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
            android.view.WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON or
            android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON
        )

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O_MR1) {
            setShowWhenLocked(true)
            setTurnScreenOn(true)
        }

        eventType = intent.getStringExtra(EXTRA_POWER_EVENT_TYPE) ?: "LOCK"
        eventTimestamp = intent.getLongExtra(EXTRA_POWER_EVENT_TIMESTAMP, 0L)

        setContent {
            TetherTheme {
                PowerEventScreen(
                    eventType = eventType,
                    onAccept = { triggerBiometricUnlock() },
                    onReject = { dismissAndFinish() },
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        eventType = intent.getStringExtra(EXTRA_POWER_EVENT_TYPE) ?: "LOCK"
        eventTimestamp = intent.getLongExtra(EXTRA_POWER_EVENT_TIMESTAMP, 0L)
    }

    private fun triggerBiometricUnlock() {
        val executor = ContextCompat.getMainExecutor(this)

        val biometricPrompt = BiometricPrompt(
            this,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    Log.i(TAG, "Biometric authentication succeeded")

                    val prefs = getSharedPreferences("tether_secure_prefs", MODE_PRIVATE)
                    prefs.edit {
                        putString("last_answered_power_event_type", eventType)
                        putLong("last_answered_power_event_timestamp_ms", eventTimestamp)
                    }
                    val serviceIntent = Intent(this@PowerEventActivity, TetherLanService::class.java).apply {
                        action = "unlock"
                    }
                    startService(serviceIntent)
                    val nm = NotificationManagerCompat.from(this@PowerEventActivity)
                    nm.cancel(PowerEventActionReceiver.POWER_EVENT_NOTIFICATION_ID)
                    nm.cancel(UnlockPromptNotifier.UNLOCK_NOTIFICATION_ID)
                    finish()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    Log.w(TAG, "Biometric authentication error ($errorCode): $errString")
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Log.w(TAG, "Biometric authentication failed")
                }
            },
        )

        val promptBuilder = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock PC")
            .setSubtitle("Confirm biometric authentication to unlock your PC")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)

        try {
            biometricPrompt.authenticate(promptBuilder.build())
        } catch (e: Exception) {
            Log.e(TAG, "Failed launching BiometricPrompt: ${e.message}")
        }
    }

    private fun dismissAndFinish() {
        val prefs = getSharedPreferences("tether_secure_prefs", MODE_PRIVATE)
        prefs.edit {
            putString("last_answered_power_event_type", eventType)
            putLong("last_answered_power_event_timestamp_ms", eventTimestamp)
        }
        val nm = NotificationManagerCompat.from(this)
        nm.cancel(PowerEventActionReceiver.POWER_EVENT_NOTIFICATION_ID)
        nm.cancel(UnlockPromptNotifier.UNLOCK_NOTIFICATION_ID)
        finish()
    }
}

@Composable
fun PowerEventScreen(
    eventType: String,
    onAccept: () -> Unit,
    onReject: () -> Unit
) {
    var isVisible by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        isVisible = true
    }

    val alphaAnim by animateFloatAsState(
        targetValue = if (isVisible) 1f else 0f,
        animationSpec = tween(400, easing = FastOutSlowInEasing),
        label = "Alpha"
    )

    val scaleAnim by animateFloatAsState(
        targetValue = if (isVisible) 1f else 0.92f,
        animationSpec = tween(400, easing = FastOutSlowInEasing),
        label = "Scale"
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.Black.copy(alpha = 0.75f * alphaAnim))
            .clickable(
                interactionSource = remember { MutableInteractionSource() },
                indication = null,
                onClick = onReject
            ),
        contentAlignment = Alignment.Center
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .graphicsLayer { alpha = 0.35f * alphaAnim }
        ) {
            DeepSpaceCanvasVisualizer()
        }

        ProfessionalGlassSurface(
            modifier = Modifier
                .fillMaxWidth(0.88f)
                .graphicsLayer {
                    scaleX = scaleAnim
                    scaleY = scaleAnim
                    alpha = alphaAnim
                }
                .clickable(
                    interactionSource = remember { MutableInteractionSource() },
                    indication = null,
                    onClick = {} // Prevent dismissal on clicking dialog body
                ),
            tint = LiquidCyan,
            alpha = 0.16f,
            blur = 32f
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                // Header Badge
                Text(
                    text = "AUTHENTICATION DIRECTIVE",
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    fontSize = 10.sp,
                    letterSpacing = 3.sp,
                    color = LiquidCyan
                )

                Spacer(modifier = Modifier.height(20.dp))

                // Cyan Icon Container
                Box(
                    modifier = Modifier
                        .size(64.dp)
                        .clip(CircleShape)
                        .background(LiquidCyan.copy(alpha = 0.12f))
                        .border(1.dp, LiquidCyan.copy(alpha = 0.4f), CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Default.Fingerprint,
                        contentDescription = "Fingerprint Authorization",
                        modifier = Modifier.size(36.dp),
                        tint = LiquidCyan
                    )
                }

                Spacer(modifier = Modifier.height(20.dp))

                Text(
                    text = "UNLOCK PC?",
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    fontSize = 20.sp,
                    letterSpacing = 2.sp,
                    color = TextPrimary
                )

                Spacer(modifier = Modifier.height(10.dp))

                Text(
                    text = "Your PC generated a ${eventType.uppercase()} directive.\nAuthorize unlock payload dispatch?",
                    fontFamily = FontFamily.SansSerif,
                    fontWeight = FontWeight.Normal,
                    fontSize = 14.sp,
                    lineHeight = 20.sp,
                    color = TextSecondary,
                    textAlign = TextAlign.Center
                )

                Spacer(modifier = Modifier.height(28.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    TacticalAction(
                        label = "DISMISS",
                        subLabel = "ABORT",
                        accentColor = AlertRed,
                        onClick = onReject,
                        modifier = Modifier.weight(1f)
                    )

                    TacticalAction(
                        label = "AUTHORIZE",
                        subLabel = "BIOMETRIC",
                        accentColor = LiquidCyan,
                        onClick = onAccept,
                        modifier = Modifier.weight(1f)
                    )
                }
            }
        }
    }
}