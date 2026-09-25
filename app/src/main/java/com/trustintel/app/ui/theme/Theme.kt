package com.trustintel.app.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val TrustIntelColors = darkColorScheme(
    primary = GlowCyan,
    secondary = GlowOrange,
    tertiary = GlowRed,
    background = CyberNavy,
    surface = CyberSurface,
    onPrimary = CyberNavy,
    onSecondary = CyberNavy,
    onTertiary = MistText,
    onBackground = MistText,
    onSurface = MistText
)

@Composable
fun TrustIntelTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = TrustIntelColors,
        typography = TrustTypography,
        content = content
    )
}
