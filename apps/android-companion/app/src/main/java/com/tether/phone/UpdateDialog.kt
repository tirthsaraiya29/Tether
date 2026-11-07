package com.tether.phone

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.tether.phone.ui.theme.*

@Composable
fun UpdateDialog(
    updateInfo: UpdateInfo,
    onDismiss: () -> Unit,
    onSnooze: (hours: Int) -> Unit,
    onDownload: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = SurfaceElevated,
        modifier = Modifier.border(
            width = 1.dp,
            brush = Brush.linearGradient(
                listOf(
                    LiquidCyan.copy(alpha = 0.6f),
                    LiquidCyan.copy(alpha = 0.15f),
                ),
            ),
            shape = RoundedCornerShape(24.dp),
        ),
        shape = RoundedCornerShape(24.dp),
        title = {
            Column {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Box(
                        modifier = Modifier
                            .size(8.dp)
                            .clip(CircleShape)
                            .background(LiquidCyan),
                    )
                    Text(
                        text = "CRITICAL UPDATE READY",
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        fontSize = 12.sp,
                        letterSpacing = 2.sp,
                        color = LiquidCyan,
                    )
                }
                Spacer(Modifier.height(8.dp))
                Text(
                    text = "v${updateInfo.latestVersion}",
                    fontWeight = FontWeight.ExtraBold,
                    fontSize = 22.sp,
                    color = TextPrimary,
                )
            }
        },
        text = {
            Column {
                Text(
                    text = "A newer version of Tether is ready to install with essential bug fixes and security updates.",
                    fontSize = 13.5.sp,
                    color = TextSecondary,
                )
                if (updateInfo.releaseNotes.isNotBlank()) {
                    Spacer(Modifier.height(10.dp))
                    Surface(
                        color = DeepSpace.copy(alpha = 0.6f),
                        shape = RoundedCornerShape(12.dp),
                        border = BorderStroke(0.5.dp, GlassBorder),
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(max = 140.dp),
                    ) {
                        Column(
                            modifier = Modifier
                                .padding(12.dp)
                                .verticalScroll(rememberScrollState()),
                        ) {
                            Text(
                                text = updateInfo.releaseNotes,
                                fontSize = 11.5.sp,
                                fontFamily = FontFamily.Monospace,
                                color = TextSecondary,
                                lineHeight = 16.sp,
                            )
                        }
                    }
                }

                Spacer(Modifier.height(14.dp))
                Text(
                    text = "REMIND ME IN:",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = TextMuted,
                    letterSpacing = 1.sp,
                )
                Spacer(Modifier.height(6.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    listOf(1 to "1 HOUR", 4 to "4 HOURS", 24 to "24 HOURS").forEach { (hrs, label) ->
                        Surface(
                            shape = RoundedCornerShape(8.dp),
                            color = SurfaceVeneer,
                            border = BorderStroke(1.dp, GlassBorder),
                            modifier = Modifier
                                .weight(1f)
                                .clip(RoundedCornerShape(8.dp))
                                .clickable { onSnooze(hrs) },
                        ) {
                            Box(
                                contentAlignment = Alignment.Center,
                                modifier = Modifier.padding(vertical = 8.dp),
                            ) {
                                Text(
                                    text = label,
                                    fontSize = 10.sp,
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    color = TextSecondary,
                                )
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = onDownload,
                enabled = updateInfo.apkDownloadUrl != null || updateInfo.releaseUrl.isNotBlank(),
                colors = ButtonDefaults.buttonColors(
                    containerColor = LiquidCyan.copy(alpha = 0.15f),
                    disabledContainerColor = SurfaceVeneer,
                ),
                border = BorderStroke(1.dp, LiquidCyan),
                shape = RoundedCornerShape(12.dp),
            ) {
                Text(
                    text = "DOWNLOAD APK",
                    color = LiquidCyan,
                    fontWeight = FontWeight.Bold,
                    style = MaterialTheme.typography.labelLarge,
                )
            }
        },
        dismissButton = {
            TextButton(onClick = { onSnooze(4) }) {
                Text(
                    text = "REMIND IN 4H",
                    color = TextSecondary,
                    fontWeight = FontWeight.Medium,
                )
            }
        },
    )
}
