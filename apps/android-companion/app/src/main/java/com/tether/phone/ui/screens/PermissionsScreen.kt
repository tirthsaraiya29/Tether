package com.tether.phone.ui.screens
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.tether.phone.ui.components.ProfessionalGlassSurface
import com.tether.phone.ui.theme.*
enum class PermissionLevel(val label: String, val badgeColor: Color) {
    CRITICAL("CRITICAL / REQUIRED", AlertRed),
    HIGH("RECOMMENDED", MatrixGold),
    OPTIONAL("OPTIONAL / ADVANCED", LiquidCyan)
}
data class PermissionItemState(
    val id: String,
    val title: String,
    val description: String,
    val level: PermissionLevel,
    val isGranted: Boolean,
    val actionText: String,
    val onClick: () -> Unit
)
@Composable
fun PermissionsScreen(
    items: List<PermissionItemState>,
    onOpenAppSettings: () -> Unit,
    onGrantAllMissing: () -> Unit,
) {
    val scrollState = rememberScrollState()
    val criticalGranted = items.filter { it.level == PermissionLevel.CRITICAL }.all { it.isGranted }
    val totalGranted = items.count { it.isGranted }
    val totalCount = items.size
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(horizontal = 24.dp, vertical = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Header Status Card
        ProfessionalGlassSurface(
            modifier = Modifier.fillMaxWidth(),
            tint = if (criticalGranted) IntegrityGreen else MatrixGold
        ) {
            Column(
                modifier = Modifier.padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Box(
                            modifier = Modifier
                                .size(40.dp)
                                .background((if (criticalGranted) IntegrityGreen else MatrixGold).copy(alpha = 0.2f), CircleShape)
                                .border(1.dp, if (criticalGranted) IntegrityGreen else MatrixGold, CircleShape),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = if (criticalGranted) Icons.Default.VerifiedUser else Icons.Default.Warning,
                                contentDescription = null,
                                tint = if (criticalGranted) IntegrityGreen else MatrixGold,
                                modifier = Modifier.size(24.dp)
                            )
                        }
                        Column {
                            Text(
                                text = "PERMISSIONS CHECKLIST",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold,
                                color = TextPrimary
                            )
                            Text(
                                text = "$totalGranted / $totalCount CONFIGURED",
                                style = MaterialTheme.typography.labelSmall,
                                color = TextSecondary
                            )
                        }
                    }
                    Surface(
                        color = (if (criticalGranted) IntegrityGreen else AlertRed).copy(alpha = 0.15f),
                        shape = RoundedCornerShape(8.dp),
                        border = BorderStroke(1.dp, if (criticalGranted) IntegrityGreen else AlertRed)
                    ) {
                        Text(
                            text = if (criticalGranted) "READY" else "ACTION REQUIRED",
                            style = MaterialTheme.typography.labelSmall,
                            color = if (criticalGranted) IntegrityGreen else AlertRed,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                        )
                    }
                }
                Text(
                    text = "Tether requires specific local network and system privileges to maintain high-speed, secure P2P communication with your host PC without background interruption.",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextMuted
                )
                if (!criticalGranted) {
                    Button(
                        onClick = onGrantAllMissing,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = LiquidCyan,
                            contentColor = Color.Black
                        ),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Default.Shield, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("GRANT CRITICAL PERMISSIONS", fontWeight = FontWeight.Bold)
                    }
                }
            }
        }
        // Group items by PermissionLevel
        PermissionLevel.entries.forEach { level ->
            val levelItems = items.filter { it.level == level }
            if (levelItems.isNotEmpty()) {
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.padding(start = 4.dp, top = 8.dp)
                    ) {
                        Box(
                            modifier = Modifier
                                .size(8.dp)
                                .background(level.badgeColor, CircleShape)
                        )
                        Text(
                            text = level.label,
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.Bold,
                            color = level.badgeColor,
                            letterSpacing = 1.sp
                        )
                    }
                    levelItems.forEach { item ->
                        PermissionCard(item = item)
                    }
                }
            }
        }
        // Open App Details Settings Button
        OutlinedButton(
            onClick = onOpenAppSettings,
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
            shape = RoundedCornerShape(12.dp),
            border = BorderStroke(1.dp, TextMuted.copy(alpha = 0.3f)),
            colors = ButtonDefaults.outlinedButtonColors(contentColor = TextSecondary)
        ) {
            Icon(Icons.Default.Settings, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(modifier = Modifier.width(8.dp))
            Text("OPEN SYSTEM APP SETTINGS", style = MaterialTheme.typography.labelMedium)
        }
        Spacer(modifier = Modifier.height(24.dp))
    }
}
@Composable
private fun PermissionCard(item: PermissionItemState) {
    ProfessionalGlassSurface(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = item.onClick),
        tint = if (item.isGranted) IntegrityGreen else item.level.badgeColor
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f).padding(end = 12.dp)) {
                Text(
                    text = item.title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = TextPrimary
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = item.description,
                    style = MaterialTheme.typography.bodySmall,
                    color = TextMuted,
                    lineHeight = 16.sp
                )
            }
            Surface(
                color = if (item.isGranted) IntegrityGreen.copy(alpha = 0.15f) else item.level.badgeColor.copy(alpha = 0.15f),
                shape = RoundedCornerShape(10.dp),
                border = BorderStroke(1.dp, if (item.isGranted) IntegrityGreen else item.level.badgeColor)
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    Icon(
                        imageVector = if (item.isGranted) Icons.Default.CheckCircle else Icons.Default.ChevronRight,
                        contentDescription = null,
                        tint = if (item.isGranted) IntegrityGreen else item.level.badgeColor,
                        modifier = Modifier.size(16.dp)
                    )
                    Text(
                        text = if (item.isGranted) "GRANTED" else item.actionText,
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = if (item.isGranted) IntegrityGreen else item.level.badgeColor
                    )
                }
            }
        }
    }
}
@Composable
fun PermissionsChecklistBanner(
    missingCount: Int,
    onReviewClick: () -> Unit,
    onDismiss: () -> Unit,
) {
    ProfessionalGlassSurface(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp),
        tint = MatrixGold
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Row(
                modifier = Modifier.weight(1f),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .background(MatrixGold.copy(alpha = 0.2f), CircleShape)
                        .border(1.dp, MatrixGold, CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Default.Shield,
                        contentDescription = null,
                        tint = MatrixGold,
                        modifier = Modifier.size(20.dp)
                    )
                }
                Column {
                    Text(
                        text = "PERMISSIONS CHECKLIST",
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.Bold,
                        color = MatrixGold
                    )
                    Text(
                        text = if (missingCount > 0)
                            "$missingCount permissions require setup for optimal link"
                        else
                            "Verify network & background permissions",
                        style = MaterialTheme.typography.bodySmall,
                        color = TextSecondary
                    )
                }
            }
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Surface(
                    onClick = onReviewClick,
                    color = MatrixGold.copy(alpha = 0.2f),
                    shape = RoundedCornerShape(8.dp),
                    border = BorderStroke(1.dp, MatrixGold)
                ) {
                    Text(
                        text = "REVIEW",
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = MatrixGold,
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp)
                    )
                }
                IconButton(
                    onClick = onDismiss,
                    modifier = Modifier.size(28.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Close,
                        contentDescription = "Dismiss",
                        tint = TextMuted,
                        modifier = Modifier.size(16.dp)
                    )
                }
            }
        }
    }
}
