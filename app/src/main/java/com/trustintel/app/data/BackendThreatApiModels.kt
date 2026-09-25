package com.trustintel.app.data

import kotlinx.serialization.Serializable

@Serializable
data class BackendUrlAnalyzeRequest(
    val url: String
)

@Serializable
data class BackendUrlAnalyzeResponse(
    val url: String,
    val trust_score: Int,
    val level: String,
    val main_reason: String,
    val findings: List<String>,
    val recommendation: String,
    val provider: String,
    val provider_used: Boolean
)

// File Analysis API Models
@Serializable
data class BackendFileAnalysisResponse(
    val filename: String,
    val file_type: String,
    val file_size: Int,
    val sha256: String,
    val trust_score: Int,
    val level: String,
    val virustotal_stats: BackendVirusTotalStats? = null,
    val malware_family: String? = null,
    val threat_labels: List<String> = emptyList(),
    val permissions: List<BackendApkPermissionInfo> = emptyList(),
    val is_apk: Boolean = false,
    val behavioral_findings: List<String> = emptyList(),
    val phishing_indicators: List<String> = emptyList(),
    val ai_explanation: String = "",
    val recommendations: List<String> = emptyList(),
    val provider: String = "",
    val analysis_timestamp: String = ""
)

@Serializable
data class BackendVirusTotalStats(
    val malicious: Int = 0,
    val suspicious: Int = 0,
    val harmless: Int = 0,
    val undetected: Int = 0,
    val timeout: Int = 0,
    val total_engines: Int = 0
)

@Serializable
data class BackendApkPermissionInfo(
    val name: String,
    val risk_level: String,
    val description: String
)
