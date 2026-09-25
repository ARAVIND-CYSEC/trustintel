package com.trustintel.app.ui

import androidx.compose.animation.AnimatedContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.widget.Toast
import androidx.compose.ui.platform.LocalContext
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.AttachFile
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Link
import androidx.compose.material.icons.outlined.Person
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material.icons.outlined.Share
import androidx.compose.material.icons.outlined.Wifi
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.trustintel.app.data.ActivityItem
import com.trustintel.app.data.FileAnalysisResult
import com.trustintel.app.data.ProfileInsight
import com.trustintel.app.data.QuickAction
import com.trustintel.app.data.RiskLevel
import com.trustintel.app.data.SecurityStatus
import com.trustintel.app.data.ShareEvent
import com.trustintel.app.data.ShareLink
import com.trustintel.app.data.UrlAnalysisResult
import com.trustintel.app.data.WifiNetwork

@Composable
fun TrustIntelApp(viewModel: TrustIntelViewModel) {
    val state by viewModel.uiState.collectAsState()
    
    // File picker launcher for Scan tab (analysis)
    val scanFilePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetMultipleContents()
    ) { uris ->
        if (uris.isNotEmpty()) {
            viewModel.ingestSharedFiles(uris)
        }
    }
    
    // File picker launcher for Share tab (secure sharing)
    val shareFilePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri ->
        if (uri != null) {
            viewModel.selectFileForShare(uri)
        }
    }
    
    val tabs = listOf(
        TrustTab.Home to Icons.Outlined.Home,
        TrustTab.Scan to Icons.Outlined.Search,
        TrustTab.Share to Icons.Outlined.Share,
        TrustTab.Wifi to Icons.Outlined.Wifi,
        TrustTab.Profile to Icons.Outlined.Person
    )

    Scaffold(
        containerColor = Color.Transparent,
        bottomBar = {
            NavigationBar(
                containerColor = Color(0xFF08111F).copy(alpha = 0.92f)
            ) {
                tabs.forEach { (tab, icon) ->
                    NavigationBarItem(
                        selected = state.activeTab == tab,
                        onClick = { viewModel.setActiveTab(tab) },
                        icon = { Icon(icon, contentDescription = tab.label) },
                        label = { Text(tab.label) }
                    )
                }
            }
        }
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(
                    Brush.verticalGradient(
                        colors = listOf(Color(0xFF020711), Color(0xFF071A2C), Color(0xFF03101D))
                    )
                )
                .padding(padding)
        ) {
            AnimatedContent(targetState = state.activeTab, label = "screen") { tab ->
                when (tab) {
                    TrustTab.Home -> HomeScreen(
                        state = state,
                        onActionTap = { route ->
                            viewModel.setActiveTab(
                                when (route) {
                                    "scan" -> TrustTab.Scan
                                    "share" -> TrustTab.Share
                                    "wifi" -> TrustTab.Wifi
                                    else -> TrustTab.Home
                                }
                            )
                        }
                    )

                    TrustTab.Scan -> ScanScreen(
                        state = state,
                        onInputChange = viewModel::updateScanInput,
                        onScan = { viewModel.runUrlScan() },
                        onPickFile = { scanFilePickerLauncher.launch("*/*") }
                    )

                    TrustTab.Share -> ShareScreen(
                        state = state,
                        onCreateLink = { viewModel.generateSecureShare() },
                        onPickFile = { shareFilePickerLauncher.launch("*/*") }
                    )

                    TrustTab.Wifi -> WifiScreen(state = state)
                    TrustTab.Profile -> ProfileScreen(state = state, onRefresh = viewModel::refresh)
                }
            }
        }
    }
}

@Composable
private fun HomeScreen(
    state: TrustIntelUiState,
    onActionTap: (String) -> Unit
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = WindowInsets.navigationBars.asPaddingValues()
    ) {
        item {
            Column(
                modifier = Modifier.padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                GlowPanel {
                    StatusCard(status = state.securityStatus)
                }
                GlowPanel {
                    SectionTitle("Quick Actions", "One-hand trust operations")
                    Spacer(modifier = Modifier.height(12.dp))
                    LazyVerticalGrid(
                        columns = GridCells.Fixed(2),
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                        userScrollEnabled = false,
                        modifier = Modifier.height(200.dp)
                    ) {
                        items(state.quickActions) { action ->
                            ActionCard(action = action, onTap = { onActionTap(action.route) })
                        }
                    }
                }
                GlowPanel {
                    SectionTitle("Recent Activity", "Latest trust decisions")
                    Spacer(modifier = Modifier.height(12.dp))
                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        state.recentActivity.forEach { item -> ActivityRow(item) }
                    }
                }
            }
        }
    }
}

@Composable
private fun ScanScreen(
    state: TrustIntelUiState,
    onInputChange: (String) -> Unit,
    onScan: () -> Unit,
    onPickFile: () -> Unit = {}
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        GlowPanel {
            SectionTitle("Link & File Analysis", "Share into the app, pick a file, or paste a suspicious URL")
            Spacer(modifier = Modifier.height(12.dp))
            OutlinedTextField(
                value = state.scanInput,
                onValueChange = onInputChange,
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Paste URL or suspicious text") },
                singleLine = true
            )
            Spacer(modifier = Modifier.height(12.dp))
            
            // File picker button
            OutlinedButton(
                onClick = onPickFile,
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(
                    imageVector = androidx.compose.material.icons.Icons.Outlined.AttachFile,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.padding(horizontal = 8.dp))
                Text("Pick File for Analysis")
            }
            Spacer(modifier = Modifier.height(12.dp))
            
            VerticalActionGroup(
                primaryLabel = "Run Scan",
                secondaryActions = listOf("Open Safely", "Share Report"),
                onPrimaryClick = onScan
            )
            Spacer(modifier = Modifier.height(12.dp))
            SignalChip(text = state.stageMessage, level = RiskLevel.Safe)
        }

        state.urlResult?.let { UrlResultCard(it) }

        if (state.fileResults.isNotEmpty()) {
            GlowPanel {
                SectionTitle("File Findings", "Shared content trust results")
                Spacer(modifier = Modifier.height(12.dp))
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    state.fileResults.forEach { FileResultCard(it) }
                }
            }
        }
    }
}

@Composable
private fun ShareScreen(
    state: TrustIntelUiState,
    onCreateLink: () -> Unit,
    onPickFile: () -> Unit = {}
) {
    val context = LocalContext.current
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        GlowPanel {
            SectionTitle("Secure File Sharing", "Enterprise-grade protected document sharing")
            Spacer(modifier = Modifier.height(12.dp))
            
            // File selection area
            Text(
                "Step 1: Select a file to share securely",
                style = MaterialTheme.typography.titleSmall,
                color = Color.White,
                fontWeight = FontWeight.SemiBold
            )
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedButton(
                onClick = {
                    onPickFile()
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(
                    imageVector = Icons.Outlined.AttachFile,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.padding(horizontal = 8.dp))
                Text("Choose File")
            }
            
            // Show selected file info
            state.selectedShareFile?.let { fileInfo ->
                Spacer(modifier = Modifier.height(12.dp))
                Card(
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0xFF0A1726)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = fileInfo.fileName,
                                style = MaterialTheme.typography.bodyMedium,
                                color = Color(0xFF47F3D5),
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            Text(
                                text = formatFileSize(fileInfo.fileSize),
                                style = MaterialTheme.typography.bodySmall,
                                color = Color(0xFF8BA5C8)
                            )
                        }
                        Icon(
                            imageVector = Icons.Outlined.CheckCircle,
                            contentDescription = "File selected",
                            tint = Color(0xFF47F3D5),
                            modifier = Modifier.size(24.dp)
                        )
                    }
                }
            }
            
            Spacer(modifier = Modifier.height(16.dp))
            
            // Generate link button
            Text(
                "Step 2: Generate secure shareable link",
                style = MaterialTheme.typography.titleSmall,
                color = Color.White,
                fontWeight = FontWeight.SemiBold
            )
            Spacer(modifier = Modifier.height(8.dp))
            Button(
                onClick = {
                    onCreateLink()
                    Toast.makeText(context, "Secure link generated!", Toast.LENGTH_SHORT).show()
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(
                    imageVector = Icons.Outlined.Link,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.padding(horizontal = 8.dp))
                Text("Generate Secure Link")
            }
            
            Spacer(modifier = Modifier.height(12.dp))
            Text(
                "End-to-end encrypted sharing with OTP verification, view-only access, expiry controls, and real-time activity tracking.",
                style = MaterialTheme.typography.bodyMedium,
                color = Color(0xFFB7C9E5)
            )
        }

        // Show generated link prominently
        state.secureShare?.let { share ->
            ShareLinkCard(share)
            
            // Copy and share actions
            GlowPanel {
                Text(
                    "Step 3: Share this link with recipients",
                    style = MaterialTheme.typography.titleSmall,
                    color = Color.White,
                    fontWeight = FontWeight.SemiBold
                )
                Spacer(modifier = Modifier.height(12.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    OutlinedButton(
                        onClick = {
                            // Copy to clipboard
                            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                            clipboard.setPrimaryClip(ClipData.newPlainText("Secure Share Link", share.secureUrl))
                            Toast.makeText(context, "Link copied to clipboard!", Toast.LENGTH_SHORT).show()
                        },
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.ContentCopy,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.padding(horizontal = 4.dp))
                        Text("Copy Link")
                    }
                    Button(
                        onClick = {
                            // Share intent
                            val sendIntent = Intent().apply {
                                action = Intent.ACTION_SEND
                                putExtra(Intent.EXTRA_TEXT, share.secureUrl)
                                type = "text/plain"
                            }
                            val shareIntent = Intent.createChooser(sendIntent, "Share secure link via")
                            context.startActivity(shareIntent)
                        },
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.Share,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.padding(horizontal = 4.dp))
                        Text("Share")
                    }
                }
            }
        }

        // Access timeline
        GlowPanel {
            SectionTitle("Access Timeline", "Real-time access analytics")
            Spacer(modifier = Modifier.height(12.dp))
            if (state.shareEvents.isEmpty()) {
                Text(
                    "No access events yet. Events will appear here when recipients access your shared file.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = Color(0xFF8BA5C8)
                )
            } else {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    state.shareEvents.forEach { event -> EventRow(event) }
                }
            }
        }
    }
}

private fun formatFileSize(bytes: Long): String {
    return when {
        bytes <= 0 -> "Unknown size"
        bytes < 1024 -> "$bytes B"
        bytes < 1024 * 1024 -> "${bytes / 1024} KB"
        bytes < 1024 * 1024 * 1024 -> "${bytes / (1024 * 1024)} MB"
        else -> "${bytes / (1024 * 1024 * 1024)} GB"
    }
}

@Composable
private fun WifiScreen(state: TrustIntelUiState) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        GlowPanel {
            SectionTitle("WiFi Security Scanner", "Nearby network trust labels")
            Spacer(modifier = Modifier.height(12.dp))
            SignalChip(text = state.connectedWifiWarning, level = RiskLevel.High)
        }

        GlowPanel {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                state.wifiNetworks.forEach { WifiCard(it) }
            }
        }
    }
}

@Composable
private fun ProfileScreen(state: TrustIntelUiState, onRefresh: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        GlowPanel {
            SectionTitle("Trust Intelligence Profile", "Operational overview")
            Spacer(modifier = Modifier.height(12.dp))
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                state.profileInsights.forEach { insight -> ProfileInsightRow(insight) }
            }
            Spacer(modifier = Modifier.height(12.dp))
            Button(onClick = onRefresh) { Text("Refresh Intelligence") }
        }
    }
}

@Composable
private fun GlowPanel(content: @Composable () -> Unit) {
    Card(
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0x22111E31)),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier
                .background(
                    Brush.linearGradient(
                        colors = listOf(Color(0x4410D7E8), Color(0x22FF4D6D), Color(0x22071A2C))
                    )
                )
                .padding(14.dp)
                .fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(0.dp)
        ) {
            content()
        }
    }
}

@Composable
private fun VerticalActionGroup(
    primaryLabel: String,
    secondaryActions: List<String>,
    onPrimaryClick: () -> Unit
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Button(
            onClick = onPrimaryClick,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(text = primaryLabel, maxLines = 1)
        }
        secondaryActions.forEach { action ->
            OutlinedButton(
                onClick = {},
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(text = action, maxLines = 1)
            }
        }
    }
}

@Composable
private fun StatusCard(status: SecurityStatus?) {
    SectionTitle("Security Status", "Live device trust posture")
    Spacer(modifier = Modifier.height(12.dp))
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.Top
    ) {
        Column(
            modifier = Modifier.fillMaxWidth(0.68f),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Text(
                text = status?.level?.label ?: "SCANNING",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = status?.level?.scoreColor ?: Color(0xFF47F3D5)
            )
            Text(
                text = "Trust Score: ${status?.trustScore ?: "--"}",
                style = MaterialTheme.typography.headlineMedium,
                color = Color.White
            )
            Text(
                text = status?.summary ?: "Loading security telemetry...",
                style = MaterialTheme.typography.bodyMedium,
                color = Color(0xFFBCD2F0),
                maxLines = 3,
                overflow = TextOverflow.Ellipsis
            )
        }
        ScoreRing(score = status?.trustScore ?: 0, level = status?.level ?: RiskLevel.Safe)
    }
    Spacer(modifier = Modifier.height(10.dp))
    SignalChip(text = status?.pulseLabel ?: "Fast scan starting", level = status?.level ?: RiskLevel.Safe)
}

@Composable
private fun ScoreRing(score: Int, level: RiskLevel) {
    Box(
        modifier = Modifier
            .size(76.dp)
            .clip(CircleShape)
            .background(level.scoreColor.copy(alpha = 0.14f)),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = score.toString(),
            color = level.scoreColor,
            style = MaterialTheme.typography.headlineMedium
        )
    }
}

@Composable
private fun ActionCard(action: QuickAction, onTap: () -> Unit) {
    Card(
        onClick = onTap,
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF0A1726))
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Icon(action.icon, contentDescription = action.title, tint = Color(0xFF47F3D5))
            Column {
                Text(action.title, color = Color.White, fontWeight = FontWeight.SemiBold, maxLines = 1)
                Text(
                    action.subtitle,
                    color = Color(0xFF9DB4D4),
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}

@Composable
private fun ActivityRow(item: ActivityItem) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.Top
    ) {
        Column(modifier = Modifier.fillMaxWidth(0.72f)) {
            Text(item.title, color = Color.White, fontWeight = FontWeight.SemiBold, maxLines = 2, overflow = TextOverflow.Ellipsis)
            Text(item.detail, color = Color(0xFF9DB4D4), style = MaterialTheme.typography.bodySmall, maxLines = 2, overflow = TextOverflow.Ellipsis)
        }
        Column(horizontalAlignment = Alignment.End) {
            SignalChip(text = item.level.label, level = item.level)
            Spacer(modifier = Modifier.height(6.dp))
            Text(item.timestamp, color = Color(0xFF7D93B2), style = MaterialTheme.typography.labelSmall)
        }
    }
}

@Composable
private fun UrlResultCard(result: UrlAnalysisResult) {
    GlowPanel {
        SectionTitle("Risk Status", result.url)
        Spacer(modifier = Modifier.height(12.dp))
        Text(
            text = "${result.level.label} RISK",
            color = result.level.scoreColor,
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold
        )
        Text(
            text = "Trust Score: ${result.trustScore}",
            color = Color.White,
            style = MaterialTheme.typography.titleMedium
        )
        Spacer(modifier = Modifier.height(12.dp))
        Text(result.mainReason, color = Color(0xFFD6E5FF))
        Spacer(modifier = Modifier.height(12.dp))
        result.findings.forEach { finding ->
            Text("- $finding", color = Color(0xFFADC3E2), maxLines = 2, overflow = TextOverflow.Ellipsis)
        }
    }
}

@Composable
private fun FileResultCard(result: FileAnalysisResult) {
    Card(
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF0B1625))
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.fillMaxWidth(0.72f)) {
                    Text(
                        text = result.name,
                        color = Color.White,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text("${result.type} Risk: ${result.level.label}", color = result.level.scoreColor)
                }
                Text("Score ${result.trustScore}", color = Color(0xFFB7C9E5))
            }
            result.findings.forEach { finding ->
                Text("- $finding", color = Color(0xFFADC3E2), maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
            if (result.permissions.isNotEmpty()) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    result.permissions.chunked(2).forEach { rowPermissions ->
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            rowPermissions.forEach { permission ->
                                AssistChip(onClick = {}, label = { Text(permission) })
                            }
                        }
                    }
                }
            }
            Text(result.explanation, color = Color(0xFFE4F1FF))
        }
    }
}

@Composable
private fun ShareLinkCard(share: ShareLink) {
    GlowPanel {
        SectionTitle("Protected Link Generated", share.fileName)
        Spacer(modifier = Modifier.height(12.dp))
        Text(share.secureUrl, color = Color(0xFF47F3D5), style = MaterialTheme.typography.titleMedium)
        Spacer(modifier = Modifier.height(8.dp))
        Text("Expires in ${share.expiresIn}", color = Color.White)
        Text("View-only: ${if (share.viewOnly) "Enabled" else "Disabled"}", color = Color(0xFFB7C9E5))
        Text("OTP verification: ${if (share.otpEnabled) "Enabled" else "Disabled"}", color = Color(0xFFB7C9E5))
    }
}

@Composable
private fun EventRow(event: ShareEvent) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Column(modifier = Modifier.fillMaxWidth(0.72f)) {
            Text(event.time, color = Color.White, fontWeight = FontWeight.SemiBold)
            Text(event.title, color = Color(0xFFDDE8F8))
            Text(event.detail, color = Color(0xFF8BA5C8), style = MaterialTheme.typography.bodySmall)
        }
        SignalChip(text = event.level.label, level = event.level)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun WifiCard(network: WifiNetwork) {
    Card(
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF0B1625))
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.fillMaxWidth(0.72f)) {
                    Text(network.ssid, color = Color.White, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(
                        text = "${network.encryption} - Signal ${network.signal}/4",
                        color = Color(0xFFADC3E2),
                        maxLines = 1
                    )
                }
                SignalChip(text = network.level.label, level = network.level)
            }
            Text(network.note, color = Color(0xFFDDE8F8))
            if (network.avoidActions.isNotEmpty()) {
                Text("Avoid:", color = network.level.scoreColor, fontWeight = FontWeight.SemiBold)
                network.avoidActions.forEach { action ->
                    Text("- $action", color = Color(0xFFADC3E2))
                }
            }
        }
    }
}

@Composable
private fun ProfileInsightRow(insight: ProfileInsight) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Column {
            Text(insight.title, color = Color.White, fontWeight = FontWeight.SemiBold)
            Text(insight.helper, color = Color(0xFF8BA5C8), style = MaterialTheme.typography.bodySmall)
        }
        Text(insight.value, color = Color(0xFF47F3D5), style = MaterialTheme.typography.titleLarge)
    }
}

@Composable
private fun SectionTitle(title: String, subtitle: String) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(
            text = title,
            style = MaterialTheme.typography.titleMedium,
            color = Color.White,
            fontWeight = FontWeight.Bold,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
        Text(
            text = subtitle,
            style = MaterialTheme.typography.bodySmall,
            color = Color(0xFF87A2C8),
            maxLines = 2,
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Composable
private fun SignalChip(text: String, level: RiskLevel) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(999.dp))
            .background(level.scoreColor.copy(alpha = 0.16f))
            .padding(horizontal = 12.dp, vertical = 8.dp)
    ) {
        Text(
            text = text,
            color = level.scoreColor,
            style = MaterialTheme.typography.labelMedium,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis
        )
    }
}
