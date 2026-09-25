package com.trustintel.app.ui

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.trustintel.app.data.ActivityItem
import com.trustintel.app.data.FileAnalysisResult
import com.trustintel.app.data.ProfileInsight
import com.trustintel.app.data.RiskLevel
import com.trustintel.app.data.SecurityStatus
import com.trustintel.app.data.SeedData
import com.trustintel.app.data.ShareEvent
import com.trustintel.app.data.ShareLink
import com.trustintel.app.data.TrustIntelRepository
import com.trustintel.app.data.UrlAnalysisResult
import com.trustintel.app.data.WifiNetwork
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class TrustIntelUiState(
    val securityStatus: SecurityStatus? = null,
    val quickActions: List<com.trustintel.app.data.QuickAction> = SeedData.quickActions,
    val recentActivity: List<ActivityItem> = emptyList(),
    val scanInput: String = "",
    val urlResult: UrlAnalysisResult? = null,
    val fileResults: List<FileAnalysisResult> = emptyList(),
    val secureShare: ShareLink? = null,
    val shareEvents: List<ShareEvent> = emptyList(),
    val wifiNetworks: List<WifiNetwork> = emptyList(),
    val profileInsights: List<ProfileInsight> = emptyList(),
    val stageMessage: String = "Quick scan ready",
    val connectedWifiWarning: String = "No unsafe WiFi connection detected.",
    val isLoading: Boolean = true,
    val activeTab: TrustTab = TrustTab.Home,
    val selectedShareFile: ShareFileInfo? = null
)

data class ShareFileInfo(
    val uri: android.net.Uri,
    val fileName: String,
    val fileSize: Long
)

enum class TrustTab(val route: String, val label: String) {
    Home("home", "Home"),
    Scan("scan", "Scan"),
    Share("share", "Share"),
    Wifi("wifi", "WiFi"),
    Profile("profile", "Profile")
}

class TrustIntelViewModel(
    application: Application,
    private val repository: TrustIntelRepository = TrustIntelRepository()
) : AndroidViewModel(application) {
    constructor(application: Application) : this(
        application = application,
        repository = TrustIntelRepository()
    )

    private val _uiState = MutableStateFlow(TrustIntelUiState())
    val uiState: StateFlow<TrustIntelUiState> = _uiState.asStateFlow()
    private var lastSharedFiles: List<Uri> = emptyList()
    private var shareFileUri: Uri? = null

    init {
        refresh()
    }

    fun refresh() {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true) }
            val wifi = repository.wifiNetworks(getApplication())
            val securityStatus = repository.loadSecurityStatus(wifi)
            val recent = repository.recentActivity()
            val events = repository.shareEvents()
            val profile = repository.profileInsights()
            val warning = wifi.firstOrNull { it.level == RiskLevel.High }?.let {
                "Unsafe WiFi detected on ${it.ssid}. Avoid sensitive logins."
            } ?: "No unsafe WiFi connection detected."

            _uiState.update {
                it.copy(
                    securityStatus = securityStatus,
                    recentActivity = recent,
                    shareEvents = events,
                    wifiNetworks = wifi,
                    profileInsights = profile,
                    connectedWifiWarning = warning,
                    isLoading = false
                )
            }
        }
    }

    fun setActiveTab(tab: TrustTab) {
        _uiState.update { it.copy(activeTab = tab) }
    }

    fun updateScanInput(input: String) {
        _uiState.update { it.copy(scanInput = input) }
    }

    fun runUrlScan(input: String = _uiState.value.scanInput) {
        if (input.isBlank()) return
        viewModelScope.launch {
            _uiState.update {
                it.copy(
                    stageMessage = "Quick scan complete. Running deep behavioral analysis...",
                    urlResult = null,
                    fileResults = emptyList(),
                    activeTab = TrustTab.Scan
                )
            }
            val result = repository.analyzeUrl(input)
            val recent = repository.recentActivity()
            val profile = repository.profileInsights()
            _uiState.update {
                it.copy(
                    scanInput = input,
                    urlResult = result,
                    stageMessage = result.recommendation,
                    recentActivity = recent,
                    profileInsights = profile
                )
            }
        }
    }

    fun ingestSharedText(text: String) {
        updateScanInput(text)
        runUrlScan(text)
    }

    fun ingestSharedFiles(files: List<Uri>) {
        viewModelScope.launch {
            lastSharedFiles = files
            _uiState.update {
                it.copy(
                    activeTab = TrustTab.Scan,
                    urlResult = null,
                    stageMessage = "Metadata extracted. Running file trust analysis..."
                )
            }
            val results = repository.analyzeFiles(getApplication(), files)
            val recent = repository.recentActivity()
            val profile = repository.profileInsights()
            _uiState.update {
                it.copy(
                    fileResults = results,
                    stageMessage = "File analysis complete. Review trust findings below.",
                    recentActivity = recent,
                    profileInsights = profile
                )
            }
        }
    }

    fun selectFileForShare(uri: Uri) {
        viewModelScope.launch {
            shareFileUri = uri
            val context = getApplication<Application>()
            val fileName = context.contentResolver.openInputStream(uri)?.use {
                uri.lastPathSegment?.substringAfterLast('/') ?: "shared-file"
            } ?: "shared-file"
            
            val fileSize = context.contentResolver.openAssetFileDescriptor(uri, "r")?.length ?: 0L
            
            _uiState.update {
                it.copy(
                    selectedShareFile = ShareFileInfo(uri, fileName, fileSize),
                    activeTab = TrustTab.Share
                )
            }
        }
    }

    fun generateSecureShare(fileName: String? = null) {
        viewModelScope.launch {
            val context = getApplication<Application>()
            
            // Use the explicitly selected share file URI first, then fall back to last shared files
            val uriToShare = shareFileUri ?: lastSharedFiles.firstOrNull()
            val actualFileName = fileName 
                ?: _uiState.value.selectedShareFile?.fileName
                ?: uriToShare?.lastPathSegment?.substringAfterLast('/') 
                ?: "shared-file"
            
            val share = repository.createSecureShare(context, actualFileName, uriToShare)
            val recent = repository.recentActivity()
            val profile = repository.profileInsights()
            _uiState.update {
                it.copy(
                    secureShare = share,
                    activeTab = TrustTab.Share,
                    recentActivity = recent,
                    profileInsights = profile
                )
            }
        }
    }
}
