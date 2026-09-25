package com.trustintel.app.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class SafeBrowsingRequest(
    val client: SafeBrowsingClient,
    @SerialName("threatInfo") val threatInfo: SafeBrowsingThreatInfo
)

@Serializable
data class SafeBrowsingClient(
    @SerialName("clientId") val clientId: String,
    @SerialName("clientVersion") val clientVersion: String
)

@Serializable
data class SafeBrowsingThreatInfo(
    @SerialName("threatTypes") val threatTypes: List<String>,
    @SerialName("platformTypes") val platformTypes: List<String>,
    @SerialName("threatEntryTypes") val threatEntryTypes: List<String>,
    @SerialName("threatEntries") val threatEntries: List<ThreatEntry>
)

@Serializable
data class ThreatEntry(
    val url: String
)

@Serializable
data class SafeBrowsingResponse(
    val matches: List<SafeBrowsingMatch> = emptyList()
)

@Serializable
data class SafeBrowsingMatch(
    @SerialName("threatType") val threatType: String,
    @SerialName("platformType") val platformType: String,
    @SerialName("threatEntryType") val threatEntryType: String
)

@Serializable
data class VirusTotalFileResponse(
    val data: VirusTotalFileData? = null
)

@Serializable
data class VirusTotalFileData(
    val id: String,
    val attributes: VirusTotalFileAttributes
)

@Serializable
data class VirusTotalFileAttributes(
    @SerialName("last_analysis_stats") val lastAnalysisStats: VirusTotalAnalysisStats? = null,
    val meaningful_name: String? = null,
    val type_description: String? = null
)

@Serializable
data class VirusTotalAnalysisStats(
    val harmless: Int = 0,
    val malicious: Int = 0,
    val suspicious: Int = 0,
    val undetected: Int = 0
)

@Serializable
data class VirusTotalUploadResponse(
    val data: VirusTotalUploadData? = null
)

@Serializable
data class VirusTotalUploadData(
    val id: String,
    val type: String
)
