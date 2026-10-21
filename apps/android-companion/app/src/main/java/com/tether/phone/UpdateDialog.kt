package com.tether.phone
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
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
                        text = "UPDATE AVAILABLE",
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
                    text = "A newer version of Tether is ready to install.",
                    fontSize = 14.sp,
                    color = TextSecondary,
                )
                if (updateInfo.releaseNotes.isNotBlank()) {
                    Spacer(Modifier.height(12.dp))
                    Surface(
                        color = DeepSpace.copy(alpha = 0.6f),
                        shape = RoundedCornerShape(12.dp),
                        border = BorderStroke(0.5.dp, GlassBorder),
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(max = 160.dp),
                    ) {
                        Column(
                            modifier = Modifier
                                .padding(12.dp)
                                .verticalScroll(rememberScrollState()),
                        ) {
                            Text(
                                text = updateInfo.releaseNotes,
                                fontSize = 12.sp,
                                fontFamily = FontFamily.Monospace,
                                color = TextSecondary,
                                lineHeight = 18.sp,
                            )
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
            TextButton(onClick = onDismiss) {
                Text(
                    text = "LATER",
                    color = TextSecondary,
                    fontWeight = FontWeight.Medium,
                )
            }
        },
    )
}
