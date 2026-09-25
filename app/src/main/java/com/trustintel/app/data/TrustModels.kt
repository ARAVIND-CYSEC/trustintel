package com.trustintel.app.data

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Link
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Share
import androidx.compose.material.icons.outlined.Wifi

enum class RiskLevel(val label: String, val scoreColor: Color) {
    Safe("SAFE", Color(0xFF47F3D5)),
    Medium("MEDIUM", Color(0xFFFF8A3D)),
    High("HIGH", Color(0xFFFF4D6D))
}

data class SecurityStatus(
    val trustScore: Int,
    val level: RiskLevel,
    val summary: String,
    val pulseLabel: String
)

data class QuickAction(
    val title: String,
    val subtitle: String,
    val icon: ImageVector,
    val route: String
)

data class ActivityItem(
    val title: String,
    val detail: String,
    val timestamp: String,
    val level: RiskLevel
)

data class UrlAnalysisResult(
    val url: String,
    val trustScore: Int,
    val level: RiskLevel,
    val mainReason: String,
    val findings: List<String>,
    val recommendation: String
)

data class FileAnalysisResult(
    val name: String,
    val type: String,
    val trustScore: Int,
    val level: RiskLevel,
    val findings: List<String>,
    val permissions: List<String>,
    val explanation: String,
    // Additional fields for comprehensive analysis
    val sha256: String = "",
    val fileSize: Long = 0L,
    val virustotalMalicious: Int = 0,
    val virustotalSuspicious: Int = 0,
    val virustotalTotal: Int = 0,
    val malwareFamily: String? = null,
    val threatLabels: List<String> = emptyList(),
    val behavioralFindings: List<String> = emptyList(),
    val phishingIndicators: List<String> = emptyList(),
    val recommendations: List<String> = emptyList(),
    val provider: String = "",
    val isApk: Boolean = false
)

data class ShareLink(
    val fileName: String,
    val trustState: RiskLevel,
    val secureUrl: String,
    val expiresIn: String,
    val viewOnly: Boolean,
    val otpEnabled: Boolean
)

data class ShareEvent(
    val time: String,
    val title: String,
    val detail: String,
    val level: RiskLevel
)

data class WifiNetwork(
    val ssid: String,
    val encryption: String,
    val signal: Int,
    val level: RiskLevel,
    val note: String,
    val avoidActions: List<String>
)

data class ProfileInsight(
    val title: String,
    val value: String,
    val helper: String
)

object SeedData {
    val quickActions = listOf(
        QuickAction("Scan URL", "Phishing & redirects", Icons.Outlined.Link, "scan"),
        QuickAction("Scan APK", "Permissions & malware", Icons.Outlined.Security, "scan"),
        QuickAction("Secure Share", "Tracked encrypted links", Icons.Outlined.Share, "share"),
        QuickAction("WiFi Check", "Unsafe network warnings", Icons.Outlined.Wifi, "wifi")
    )
}
