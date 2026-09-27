package com.tether.phone

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.tether.phone.ui.components.DeepSpaceCanvasVisualizer
import com.tether.phone.ui.components.ProfessionalGlassSurface
import com.tether.phone.ui.components.TacticalAction
import com.tether.phone.ui.theme.AlertRed
import com.tether.phone.ui.theme.DeepSpace
import com.tether.phone.ui.theme.IntegrityGreen
import com.tether.phone.ui.theme.LiquidCyan
import com.tether.phone.ui.theme.TetherTheme
import com.tether.phone.ui.theme.TextPrimary
import com.tether.phone.ui.theme.TextSecondary
import kotlinx.coroutines.delay

class PairingConfirmationActivity : ComponentActivity() {

    private var requestId: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)

        requestId = intent.getStringExtra(TetherLanService.EXTRA_PAIRING_REQUEST_ID) ?: ""
        val peerName = intent.getStringExtra(TetherLanService.EXTRA_PEER_DEVICE_NAME) ?: "Windows PC"
        val peerFingerprint = intent.getStringExtra(TetherLanService.EXTRA_WINDOWS_FINGERPRINT) ?: "NONE"
        val sasCode = intent.getStringExtra(TetherLanService.EXTRA_PAIRING_SAS_CODE) ?: "000000"

        setContent {
            TetherTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = DeepSpace
                ) {
                    PairingConfirmationContent(
                        peerName = peerName,
                        peerFingerprint = peerFingerprint,
                        sasCode = sasCode,
                        onAccept = {
                            confirmPairing()
                        },
                        onReject = {
                            rejectPairing()
                        },
                        onTimeout = {
                            rejectPairing()
                        }
                    )
                }
            }
        }
    }

    private fun confirmPairing() {
        val intent = Intent(this, TetherLanService::class.java).apply {
            action = TetherLanService.ACTION_CONFIRM_PAIRING
            putExtra(TetherLanService.EXTRA_PAIRING_REQUEST_ID, requestId)
        }
        startForegroundService(intent)
        finish()
    }

    private fun rejectPairing() {
        val intent = Intent(this, TetherLanService::class.java).apply {
            action = TetherLanService.ACTION_REJECT_PAIRING
            putExtra(TetherLanService.EXTRA_PAIRING_REQUEST_ID, requestId)
        }
        startForegroundService(intent)
        finish()
    }
}

@Composable
fun PairingConfirmationContent(
    peerName: String,
    peerFingerprint: String,
    sasCode: String,
    onAccept: () -> Unit,
    onReject: () -> Unit,
    onTimeout: () -> Unit
) {
    var secondsLeft by remember { mutableIntStateOf(60) }

    LaunchedEffect(Unit) {
        while (secondsLeft > 0) {
            delay(1000L)
            secondsLeft -= 1
        }
        onTimeout()
    }

    val progress by animateFloatAsState(
        targetValue = secondsLeft / 60f,
        animationSpec = tween(durationMillis = 1000, easing = LinearEasing),
        label = "Countdown"
    )

    val formattedSas = if (sasCode.length == 6) {
        "${sasCode.substring(0, 3)} ${sasCode.substring(3, 6)}"
    } else {
        sasCode
    }

    val formattedFpLines = if (peerFingerprint.length > 32) {
        val mid = peerFingerprint.length / 2
        "${peerFingerprint.substring(0, mid)}\n${peerFingerprint.substring(mid)}"
    } else {
        peerFingerprint
    }

    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        DeepSpaceCanvasVisualizer()

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            ProfessionalGlassSurface(
                modifier = Modifier.fillMaxWidth(),
                tint = LiquidCyan,
                alpha = 0.18f,
                blur = 50f
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Box(contentAlignment = Alignment.Center) {
                        CircularProgressIndicator(
                            progress = { progress },
                            color = LiquidCyan,
                            trackColor = Color.White.copy(alpha = 0.1f),
                            strokeWidth = 4.dp,
                            modifier = Modifier.size(72.dp)
                        )
                        Text(
                            text = "${secondsLeft}s",
                            color = LiquidCyan,
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.Bold
                        )
                    }

                    Spacer(modifier = Modifier.height(24.dp))

                    Text(
                        text = "Pair with $peerName?",
                        style = MaterialTheme.typography.headlineSmall,
                        color = TextPrimary,
                        fontWeight = FontWeight.ExtraBold,
                        textAlign = TextAlign.Center
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(12.dp))
                            .background(LiquidCyan.copy(alpha = 0.12f))
                            .padding(horizontal = 14.dp, vertical = 6.dp)
                    ) {
                        Text(
                            text = "ML-KEM-768 + ML-DSA-65 (PQC Encrypted)",
                            style = MaterialTheme.typography.labelSmall,
                            color = LiquidCyan,
                            fontWeight = FontWeight.SemiBold
                        )
                    }

                    Spacer(modifier = Modifier.height(28.dp))

                    Text(
                        text = "SECURITY AUTHENTICATION CODE",
                        style = MaterialTheme.typography.labelSmall,
                        color = TextSecondary,
                        letterSpacing = 2.sp
                    )

                    Spacer(modifier = Modifier.height(8.dp))

                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(20.dp))
                            .background(Color.Black.copy(alpha = 0.45f))
                            .padding(vertical = 18.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = formattedSas,
                            fontSize = 36.sp,
                            fontWeight = FontWeight.ExtraBold,
                            fontFamily = FontFamily.Monospace,
                            color = LiquidCyan,
                            letterSpacing = 6.sp
                        )
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    Text(
                        text = "Compare this code with the prompt on your PC",
                        style = MaterialTheme.typography.bodySmall,
                        color = TextSecondary,
                        textAlign = TextAlign.Center
                    )

                    Spacer(modifier = Modifier.height(24.dp))

                    Text(
                        text = "WINDOWS HOST FINGERPRINT",
                        style = MaterialTheme.typography.labelSmall,
                        color = TextSecondary,
                        letterSpacing = 2.sp
                    )

                    Spacer(modifier = Modifier.height(6.dp))

                    Text(
                        text = formattedFpLines,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        color = TextPrimary,
                        textAlign = TextAlign.Center,
                        lineHeight = 16.sp
                    )

                    Spacer(modifier = Modifier.height(32.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        TacticalAction(
                            label = stringResource(R.string.btn_reject),
                            accentColor = AlertRed,
                            onClick = onReject,
                            modifier = Modifier.weight(1f)
                        )
                        TacticalAction(
                            label = stringResource(R.string.btn_accept),
                            accentColor = IntegrityGreen,
                            onClick = onAccept,
                            modifier = Modifier.weight(1f)
                        )
                    }
                }
            }
        }
    }
}
