package com.trustintel.app.data

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.database.Cursor
import android.net.ConnectivityManager
import android.net.Uri
import android.net.wifi.ScanResult
import android.net.wifi.WifiManager
import android.os.Build
import android.provider.OpenableColumns
import androidx.core.content.ContextCompat
import com.trustintel.app.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.RequestBody.Companion.asRequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Request
import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import java.time.LocalTime
import java.time.OffsetDateTime
import java.time.format.DateTimeFormatter
import java.util.Locale
import kotlin.random.Random

class TrustIntelRepository {
    private data class BackendUrlAttempt(
        val result: UrlAnalysisResult? = null,
        val attemptedBaseUrl: String? = null,
        val errorMessage: String? = null
    )

    private val activities = mutableListOf<ActivityItem>(
        ActivityItem(
            title = "Trust engine initialized",
            detail = "Live device intelligence is ready.",
            timestamp = "now",
            level = RiskLevel.Safe
        )
    )
    private val httpClient = OkHttpClient.Builder()
        .followRedirects(false)
        .followSslRedirects(false)
        .connectTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
        .readTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
        .writeTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
        .retryOnConnectionFailure(true)
        .build()
    private val json = Json { ignoreUnknownKeys = true }

    suspend fun loadSecurityStatus(wifiNetworks: List<WifiNetwork>): SecurityStatus = withContext(Dispatchers.Default) {
        val highCount = wifiNetworks.count { it.level == RiskLevel.High }
        val mediumCount = wifiNetworks.count { it.level == RiskLevel.Medium }
        val trustScore = (100 - (highCount * 28) - (mediumCount * 12)).coerceIn(24, 96)
        val level = when {
            trustScore >= 75 -> RiskLevel.Safe
            trustScore >= 45 -> RiskLevel.Medium
            else -> RiskLevel.High
        }
        val summary = when (level) {
            RiskLevel.Safe -> "Device posture looks stable. No critical local trust issues detected."
            RiskLevel.Medium -> "Caution advised. Some network or content signals need review."
            RiskLevel.High -> "Risk exposure detected. Review recent scans and network choices."
        }
        val pulse = when {
            highCount > 0 -> "High-risk network signal active"
            mediumCount > 0 -> "Watching medium-risk trust events"
            else -> "Live trust monitoring active"
        }
        SecurityStatus(
            trustScore = trustScore,
            level = level,
            summary = summary,
            pulseLabel = pulse
        )
    }

    suspend fun recentActivity(): List<ActivityItem> {
        delay(120)
        return activities.take(6)
    }

    suspend fun analyzeUrl(input: String): UrlAnalysisResult {
        return withContext(Dispatchers.IO) {
            val backendBaseUrl = BuildConfig.SECURE_SHARE_BASE_URL.trim().trimEnd('/')
            if (backendBaseUrl.isNotBlank()) {
                val backendAttempt = analyzeUrlViaBackend(backendBaseUrl, input)
                if (backendAttempt.result != null) {
                    val backendResult = backendAttempt.result
                    recordActivity(
                        title = "URL scanned",
                        detail = "${backendResult.url} scored ${backendResult.trustScore}",
                        level = backendResult.level
                    )
                    return@withContext backendResult
                }

                return@withContext UrlAnalysisResult(
                    url = normalizeUrl(input),
                    trustScore = 18,
                    level = RiskLevel.High,
                    mainReason = "Backend URL analysis failed.",
                    findings = listOf(
                        "The app could not fetch a backend result from ${backendAttempt.attemptedBaseUrl ?: backendBaseUrl}.",
                        "No trusted API verdict was returned.",
                        backendAttempt.errorMessage ?: "Check SECURE_SHARE_BASE_URL and backend logs."
                    ),
                    recommendation = "Do not rely on this scan until the backend API is reachable."
                )
            }

            UrlAnalysisResult(
                url = input.trim(),
                trustScore = 10,
                level = RiskLevel.High,
                mainReason = "Backend URL analysis is not configured.",
                findings = listOf(
                    "SECURE_SHARE_BASE_URL is empty.",
                    "The app is not calling the backend API for URL analysis.",
                    "Add the backend URL and rebuild the app."
                ),
                recommendation = "Configure the backend before relying on pasted URL analysis."
            )
        }
    }

    suspend fun analyzeFiles(context: Context, files: List<Uri>): List<FileAnalysisResult> = withContext(Dispatchers.IO) {
        files.map { uri ->
            analyzeSingleFile(context, uri)
        }
    }

    private fun analyzeSingleFile(context: Context, uri: Uri): FileAnalysisResult {
        // First try backend analysis if configured
        val backendBaseUrl = BuildConfig.SECURE_SHARE_BASE_URL.trim().trimEnd('/')
        if (backendBaseUrl.isNotBlank()) {
            val backendResult = analyzeFileViaBackend(context, uri, backendBaseUrl)
            if (backendResult != null) {
                recordActivity("File analyzed via backend", "${backendResult.name} scored ${backendResult.trustScore}", backendResult.level)
                return backendResult
            }
        }
        
        // Fallback to local analysis
        return analyzeFileLocally(context, uri)
    }

    private fun analyzeFileLocally(context: Context, uri: Uri): FileAnalysisResult {
        val resolver = context.contentResolver
        val name = queryDisplayName(resolver.query(uri, null, null, null, null)) ?: uri.lastPathSegment?.substringAfterLast('/') ?: "shared-file"
        val mimeType = resolver.getType(uri) ?: "application/octet-stream"
        val sizeBytes = resolver.openAssetFileDescriptor(uri, "r")?.use { it.length } ?: -1L
        val sha256 = resolver.openInputStream(uri)?.use { digestSha256(it) } ?: "unavailable"
        val isApk = name.endsWith(".apk", ignoreCase = true) || mimeType.contains("android.package-archive")

        if (isApk) {
            val archiveFile = copyUriToCache(context, uri, name)
            val packageInfo = context.packageManager.getPackageArchiveInfo(
                archiveFile.absolutePath,
                PackageManager.GET_PERMISSIONS
            )
            val requestedPermissions = packageInfo?.requestedPermissions?.toList().orEmpty()
            val riskyPermissions = requestedPermissions.filter { permission ->
                permission.contains("SMS") ||
                    permission.contains("SYSTEM_ALERT_WINDOW") ||
                    permission.contains("REQUEST_INSTALL_PACKAGES") ||
                    permission.contains("WRITE_SETTINGS") ||
                    permission.contains("READ_CONTACTS") ||
                    permission.contains("READ_CALL_LOG")
            }
            val score = (88 - (riskyPermissions.size * 14) - (requestedPermissions.size / 3)).coerceIn(14, 92)
            val level = levelFromScore(score)
            val findings = mutableListOf(
                "Package permissions parsed from the APK manifest.",
                "SHA-256: ${sha256.take(16)}..."
            )
            if (sizeBytes > 0) {
                findings += "File size: ${humanFileSize(sizeBytes)}."
            }
            if (riskyPermissions.isNotEmpty()) {
                findings += "Potentially dangerous permissions detected."
            }
            val vtVerdict = lookupVirusTotalFile(sha256)
            val adjustedScore = adjustScoreWithVirusTotal(score, vtVerdict)
            val adjustedLevel = levelFromScore(adjustedScore)
            if (vtVerdict != null) {
                findings += vtVerdict.summary
            } else if (BuildConfig.VIRUSTOTAL_API_KEY.isNotBlank() && sizeBytes in 1..(32L * 1024L * 1024L)) {
                val uploadId = uploadFileToVirusTotal(archiveFile)
                if (uploadId != null) {
                    findings += "VirusTotal upload submitted for deeper analysis."
                }
            }
            val explanation = when {
                riskyPermissions.any { it.contains("SMS") } ->
                    "This APK may read or send SMS messages, which can expose OTPs."
                riskyPermissions.any { it.contains("SYSTEM_ALERT_WINDOW") } ->
                    "This APK can draw over other apps, which is commonly abused in phishing overlays."
                else ->
                    "APK metadata was parsed successfully. Review permissions before installation."
            }
            val result = FileAnalysisResult(
                name = name,
                type = "APK",
                trustScore = adjustedScore,
                level = adjustedLevel,
                findings = findings.take(5),
                permissions = riskyPermissions.map { it.substringAfterLast('.') }.ifEmpty {
                    requestedPermissions.take(4).map { it.substringAfterLast('.') }
                },
                explanation = explanation,
                sha256 = sha256,
                fileSize = sizeBytes,
                virustotalMalicious = vtVerdict?.malicious ?: 0,
                virustotalSuspicious = vtVerdict?.suspicious ?: 0,
                virustotalTotal = vtVerdict?.let { it.malicious + it.suspicious + it.harmless } ?: 0,
                isApk = true
            )
            recordActivity("APK analyzed", "$name scored ${result.trustScore}", result.level)
            return result
        } else {
            val findings = mutableListOf(
                "MIME type: $mimeType.",
                "SHA-256: ${sha256.take(16)}..."
            )
            if (sizeBytes > 0) {
                findings += "File size: ${humanFileSize(sizeBytes)}."
            }
            val suspiciousName = name.contains("invoice", true) ||
                name.contains("payment", true) ||
                name.contains("resume", true) ||
                name.contains("password", true)
            val baseScore = if (suspiciousName) 58 else 76
            val vtVerdict = lookupVirusTotalFile(sha256)
            val score = adjustScoreWithVirusTotal(baseScore, vtVerdict)
            val level = levelFromScore(score)
            if (vtVerdict != null) {
                findings += vtVerdict.summary
            }
            val result = FileAnalysisResult(
                name = name,
                type = name.substringAfterLast('.', "File").uppercase(Locale.US),
                trustScore = score,
                level = level,
                findings = findings.take(4),
                permissions = emptyList(),
                explanation = if (suspiciousName) {
                    "The filename pattern is commonly used in lures. Verify the sender before opening."
                } else if (vtVerdict != null) {
                    "External reputation data was merged with local metadata analysis."
                } else {
                    "Live metadata was collected. Deeper malware verdicts still require a backend engine."
                },
                sha256 = sha256,
                fileSize = sizeBytes,
                virustotalMalicious = vtVerdict?.malicious ?: 0,
                virustotalSuspicious = vtVerdict?.suspicious ?: 0,
                virustotalTotal = vtVerdict?.let { it.malicious + it.suspicious + it.harmless } ?: 0
            )
            recordActivity("File analyzed", "$name scored ${result.trustScore}", result.level)
            return result
        }
    }

    private fun analyzeFileViaBackend(context: Context, uri: Uri, baseUrl: String): FileAnalysisResult? {
        return runCatching {
            val resolver = context.contentResolver
            val name = queryDisplayName(resolver.query(uri, null, null, null, null)) ?: uri.lastPathSegment?.substringAfterLast('/') ?: "file"
            val mimeType = resolver.getType(uri) ?: "application/octet-stream"
            
            // Create a temp file for upload
            val tempFile = copyUriToCache(context, uri, name)
            
            // Create multipart request
            val mediaType = mimeType.toMediaType()
            val fileRequestBody = tempFile.asRequestBody(mediaType)
            
            val requestBody = MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addFormDataPart("file", name, fileRequestBody)
                .build()

            val request = Request.Builder()
                .url("$baseUrl/analyze/file")
                .post(requestBody)
                .build()

            httpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return null
                
                val body = response.body?.string().orEmpty()
                val parsed = json.decodeFromString<BackendFileAnalysisResponse>(body)
                
                // Convert backend response to local model
                val level = when (parsed.level.uppercase(Locale.US)) {
                    "HIGH" -> RiskLevel.High
                    "MEDIUM" -> RiskLevel.Medium
                    else -> RiskLevel.Safe
                }
                
                val findings = mutableListOf<String>()
                findings.addAll(parsed.behavioral_findings)
                if (parsed.ai_explanation.isNotBlank()) {
                    findings.add(parsed.ai_explanation)
                }
                
                FileAnalysisResult(
                    name = parsed.filename,
                    type = parsed.file_type,
                    trustScore = parsed.trust_score,
                    level = level,
                    findings = findings.take(5),
                    permissions = parsed.permissions.map { it.name },
                    explanation = parsed.ai_explanation.ifBlank { parsed.behavioral_findings.firstOrNull() ?: "File analysis completed." },
                    sha256 = parsed.sha256,
                    fileSize = parsed.file_size.toLong(),
                    virustotalMalicious = parsed.virustotal_stats?.malicious ?: 0,
                    virustotalSuspicious = parsed.virustotal_stats?.suspicious ?: 0,
                    virustotalTotal = parsed.virustotal_stats?.total_engines ?: 0,
                    malwareFamily = parsed.malware_family,
                    threatLabels = parsed.threat_labels,
                    behavioralFindings = parsed.behavioral_findings,
                    phishingIndicators = parsed.phishing_indicators,
                    recommendations = parsed.recommendations,
                    provider = parsed.provider,
                    isApk = parsed.is_apk
                )
            }
        }.getOrNull()
    }

    suspend fun createSecureShare(context: Context, fileName: String, sourceUri: Uri? = null): ShareLink = withContext(Dispatchers.IO) {
        val baseUrl = BuildConfig.SECURE_SHARE_BASE_URL.trim().trimEnd('/')
        if (baseUrl.isBlank()) {
            val token = Random.nextInt(100000, 999999)
            val fallback = ShareLink(
                fileName = fileName,
                trustState = RiskLevel.Medium,
                secureUrl = "Configure SECURE_SHARE_BASE_URL to enable backend sharing",
                expiresIn = "24 hours",
                viewOnly = true,
                otpEnabled = true
            )
            recordActivity("Secure share pending", "Backend URL not configured for $fileName", RiskLevel.Medium)
            return@withContext fallback
        }

        val tempFile = if (sourceUri != null) {
            copyUriToCache(context, sourceUri, fileName)
        } else {
            File(context.cacheDir, fileName).apply {
                if (!exists()) {
                    writeText("TrustIntel secure share placeholder for $fileName")
                }
            }
        }

        val requestBody = MultipartBody.Builder()
            .setType(MultipartBody.FORM)
            .addFormDataPart(
                "file",
                tempFile.name,
                tempFile.asRequestBody("application/octet-stream".toMediaType())
            )
            .addFormDataPart("expires_hours", "24")
            .addFormDataPart("view_only", "true")
            .addFormDataPart("otp_enabled", "true")
            .build()

        val request = Request.Builder()
            .url("$baseUrl/shares")
            .post(requestBody)
            .build()

        runCatching {
            httpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) error("Share API failed with ${response.code}")
                val payload = json.decodeFromString<ShareCreateApiResponse>(response.body?.string().orEmpty())
                logShareEvent(
                    baseUrl = baseUrl,
                    shareId = payload.share_id,
                    action = "opened",
                    detail = "Android client generated a secure share."
                )
                val link = ShareLink(
                    fileName = payload.file_name,
                    trustState = RiskLevel.Safe,
                    secureUrl = if (payload.secure_url.startsWith("http")) payload.secure_url else "$baseUrl${payload.secure_url}",
                    expiresIn = formatExpiry(payload.expires_at),
                    viewOnly = payload.view_only,
                    otpEnabled = payload.otp_enabled
                )
                recordActivity("Secure link created", payload.file_name, RiskLevel.Safe)
                link
            }
        }.getOrElse {
            recordActivity("Secure share failed", it.message ?: "backend error", RiskLevel.High)
            ShareLink(
                fileName = fileName,
                trustState = RiskLevel.High,
                secureUrl = "Share failed: ${it.message ?: "backend error"}",
                expiresIn = "Unavailable",
                viewOnly = true,
                otpEnabled = true
            )
        }
    }

    suspend fun shareEvents(): List<ShareEvent> {
        delay(200)
        return listOf(
            ShareEvent("10:30 AM", "Opened from Android", "Secure viewer session established", RiskLevel.Safe),
            ShareEvent("11:05 AM", "Download attempted", "View-only policy blocked export", RiskLevel.Medium),
            ShareEvent("11:18 AM", "OTP verified", "Recipient identity confirmed", RiskLevel.Safe)
        )
    }

    suspend fun wifiNetworks(context: Context): List<WifiNetwork> = withContext(Dispatchers.IO) {
        if (!hasWifiPermissions(context)) {
            return@withContext listOf(
                WifiNetwork(
                    ssid = "Permission required",
                    encryption = "Unknown",
                    signal = 0,
                    level = RiskLevel.Medium,
                    note = "Grant WiFi and location permissions to scan nearby networks in real time.",
                    avoidActions = listOf("Open the app again after granting permissions")
                )
            )
        }

        val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val activeNetwork = connectivityManager.activeNetwork
        val onWifi = connectivityManager.getNetworkCapabilities(activeNetwork)?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) == true
        val connectedSsid = runCatching { wifiManager.connectionInfo?.ssid?.removeSurrounding("\"") }.getOrNull()

        val results = wifiManager.scanResults
            .sortedByDescending { it.level }
            .distinctBy { it.SSID }
            .take(8)
            .map { scan ->
                val encryption = parseEncryption(scan)
                val signal = signalBuckets(scan.level)
                val level = when (encryption) {
                    "Open", "WEP" -> RiskLevel.High
                    "WPA", "WPA2" -> RiskLevel.Medium
                    else -> RiskLevel.Safe
                }
                val note = when (level) {
                    RiskLevel.High -> "Open or weak encryption detected. Avoid sensitive logins on this network."
                    RiskLevel.Medium -> "Protected network detected, but use caution for banking or identity flows."
                    RiskLevel.Safe -> "Modern WiFi protection detected."
                }
                WifiNetwork(
                    ssid = if (scan.SSID.isBlank()) "<Hidden network>" else scan.SSID,
                    encryption = encryption,
                    signal = signal,
                    level = level,
                    note = if (onWifi && connectedSsid == scan.SSID) "Currently connected. $note" else note,
                    avoidActions = when (level) {
                        RiskLevel.High -> listOf("Banking apps", "OTP logins", "Sensitive document uploads")
                        RiskLevel.Medium -> listOf("Password resets", "Corporate VPN onboarding")
                        RiskLevel.Safe -> emptyList()
                    }
                )
            }

        if (results.isNotEmpty()) {
            val highest = results.minByOrNull { it.trustRank() }
            if (highest != null) {
                recordActivity("WiFi scan completed", "${highest.ssid} marked ${highest.level.label}", highest.level)
            }
        }
        results.ifEmpty {
            listOf(
                WifiNetwork(
                    ssid = "No nearby networks",
                    encryption = "Unknown",
                    signal = 0,
                    level = RiskLevel.Safe,
                    note = "No scan results were returned by the device at this moment.",
                    avoidActions = emptyList()
                )
            )
        }
    }

    suspend fun profileInsights(): List<ProfileInsight> {
        delay(160)
        return listOf(
            ProfileInsight("Threat Detections", activities.count { it.level == RiskLevel.High }.toString(), "Current session"),
            ProfileInsight("Secure Shares", "1", "Backend flow still mocked"),
            ProfileInsight("WiFi Alerts", activities.count { it.title.contains("WiFi") }.toString(), "Current session")
        )
    }

    private fun normalizeUrl(input: String): String {
        val trimmed = input.trim()
        return if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) trimmed else "https://$trimmed"
    }

    private suspend fun lookupSafeBrowsing(url: String): SafeBrowsingVerdict? {
        val key = BuildConfig.SAFE_BROWSING_API_KEY
        if (key.isBlank()) return null
        return runCatching {
            val endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=$key"
            val payload = SafeBrowsingRequest(
                client = SafeBrowsingClient(
                    clientId = "trustintel-android",
                    clientVersion = "1.0.0"
                ),
                threatInfo = SafeBrowsingThreatInfo(
                    threatTypes = listOf(
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION"
                    ),
                    platformTypes = listOf("ANY_PLATFORM"),
                    threatEntryTypes = listOf("URL"),
                    threatEntries = listOf(ThreatEntry(url))
                )
            )
            val request = Request.Builder()
                .url(endpoint)
                .post(json.encodeToString(payload).toRequestBody("application/json".toMediaType()))
                .build()
            httpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return@use null
                val body = response.body?.string().orEmpty()
                val parsed = json.decodeFromString<SafeBrowsingResponse>(body)
                if (parsed.matches.isEmpty()) {
                    SafeBrowsingVerdict(false, "no matches")
                } else {
                    SafeBrowsingVerdict(true, parsed.matches.joinToString { it.threatType })
                }
            }
        }.getOrNull()
    }

    private fun lookupVirusTotalFile(sha256: String): VirusTotalVerdict? {
        val key = BuildConfig.VIRUSTOTAL_API_KEY
        if (key.isBlank()) return null
        return runCatching {
            val request = Request.Builder()
                .url("https://www.virustotal.com/api/v3/files/$sha256")
                .header("x-apikey", key)
                .get()
                .build()
            httpClient.newCall(request).execute().use { response ->
                if (response.code == 404) return@use null
                if (!response.isSuccessful) return@use null
                val body = response.body?.string().orEmpty()
                val parsed = json.decodeFromString<VirusTotalFileResponse>(body)
                val stats = parsed.data?.attributes?.lastAnalysisStats ?: return@use null
                VirusTotalVerdict(
                    malicious = stats.malicious,
                    suspicious = stats.suspicious,
                    harmless = stats.harmless,
                    summary = "VirusTotal verdict: ${stats.malicious} malicious, ${stats.suspicious} suspicious."
                )
            }
        }.getOrNull()
    }

    private fun uploadFileToVirusTotal(file: File): String? {
        val key = BuildConfig.VIRUSTOTAL_API_KEY
        if (key.isBlank()) return null
        return runCatching {
            val body = MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addFormDataPart(
                    "file",
                    file.name,
                    file.asRequestBody("application/octet-stream".toMediaType())
                )
                .build()
            val request = Request.Builder()
                .url("https://www.virustotal.com/api/v3/files")
                .header("x-apikey", key)
                .post(body)
                .build()
            httpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return@use null
                val parsed = json.decodeFromString<VirusTotalUploadResponse>(response.body?.string().orEmpty())
                parsed.data?.id
            }
        }.getOrNull()
    }

    private fun adjustScoreWithVirusTotal(baseScore: Int, verdict: VirusTotalVerdict?): Int {
        if (verdict == null) return baseScore
        val penalty = (verdict.malicious * 9) + (verdict.suspicious * 4)
        return (baseScore - penalty).coerceIn(8, 96)
    }

    private fun recommendationWithBackend(base: String, hasSafeBrowsing: Boolean): String {
        return if (hasSafeBrowsing) "$base Reputation feed included." else base
    }

    private fun analyzeUrlViaBackend(baseUrl: String, input: String): BackendUrlAttempt {
        val attempts = buildBackendBaseUrls(baseUrl)
        var lastError = "Backend request failed before a response was returned."

        for (candidateBaseUrl in attempts) {
            val outcome = runCatching {
            val body = json.encodeToString(
                BackendUrlAnalyzeRequest(url = input.trim())
            ).toRequestBody("application/json".toMediaType())
            val request = Request.Builder()
                    .url("$candidateBaseUrl/analyze/url")
                .post(body)
                .build()
            httpClient.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) {
                        error("Backend returned HTTP ${response.code}")
                    }
                val payload = json.decodeFromString<BackendUrlAnalyzeResponse>(response.body?.string().orEmpty())
                UrlAnalysisResult(
                    url = payload.url,
                    trustScore = payload.trust_score,
                    level = when (payload.level.uppercase(Locale.US)) {
                        "HIGH" -> RiskLevel.High
                        "MEDIUM" -> RiskLevel.Medium
                        else -> RiskLevel.Safe
                    },
                    mainReason = "${payload.main_reason} Source: ${payload.provider}.",
                    findings = payload.findings + listOf(
                        "Provider: ${payload.provider}",
                        "Provider used: ${payload.provider_used}"
                    ),
                    recommendation = payload.recommendation
                )
            }
            }

            outcome.getOrNull()?.let { result ->
                return BackendUrlAttempt(
                    result = result,
                    attemptedBaseUrl = candidateBaseUrl
                )
            }

            lastError = outcome.exceptionOrNull()?.message ?: lastError
        }

        return BackendUrlAttempt(
            attemptedBaseUrl = attempts.lastOrNull() ?: baseUrl,
            errorMessage = lastError
        )
    }

    private fun buildBackendBaseUrls(baseUrl: String): List<String> {
        val parsed = baseUrl.toHttpUrlOrNull() ?: return listOf(baseUrl)
        val candidates = linkedSetOf(baseUrl)
        val host = parsed.host.lowercase(Locale.US)

        if (host == "localhost" || host == "127.0.0.1") {
            candidates += parsed.newBuilder().host("10.0.2.2").build().toString().trimEnd('/')
        }

        return candidates.toList()
    }

    private fun logShareEvent(baseUrl: String, shareId: String, action: String, detail: String) {
        val body = json.encodeToString(
            ShareAccessEventRequest(
                action = action,
                platform = "android",
                detail = detail
            )
        ).toRequestBody("application/json".toMediaType())
        val request = Request.Builder()
            .url("$baseUrl/shares/$shareId/events")
            .post(body)
            .build()
        runCatching {
            httpClient.newCall(request).execute().close()
        }
    }

    private fun levelFromScore(score: Int): RiskLevel = when {
        score >= 75 -> RiskLevel.Safe
        score >= 45 -> RiskLevel.Medium
        else -> RiskLevel.High
    }

    private fun recordActivity(title: String, detail: String, level: RiskLevel) {
        activities.add(
            0,
            ActivityItem(
                title = title,
                detail = detail,
                timestamp = LocalTime.now().format(DateTimeFormatter.ofPattern("h:mm a")),
                level = level
            )
        )
    }

    private fun hasWifiPermissions(context: Context): Boolean {
        val hasLocation = ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.ACCESS_FINE_LOCATION
        ) == PackageManager.PERMISSION_GRANTED
        val hasNearby = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.NEARBY_WIFI_DEVICES
            ) == PackageManager.PERMISSION_GRANTED
        } else {
            true
        }
        return hasLocation && hasNearby
    }

    private fun parseEncryption(scanResult: ScanResult): String {
        val caps = scanResult.capabilities.uppercase(Locale.US)
        return when {
            caps.contains("WPA3") -> "WPA3"
            caps.contains("WPA2") -> "WPA2"
            caps.contains("WPA") -> "WPA"
            caps.contains("WEP") -> "WEP"
            else -> "Open"
        }
    }

    private fun signalBuckets(level: Int): Int = when {
        level >= -55 -> 4
        level >= -67 -> 3
        level >= -77 -> 2
        level >= -88 -> 1
        else -> 0
    }

    private fun copyUriToCache(context: Context, uri: Uri, fileName: String): File {
        val target = File(context.cacheDir, fileName)
        context.contentResolver.openInputStream(uri)?.use { input ->
            target.outputStream().use { output -> input.copyTo(output) }
        }
        return target
    }

    private fun digestSha256(input: InputStream): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        var bytesRead = input.read(buffer)
        while (bytesRead >= 0) {
            if (bytesRead > 0) {
                digest.update(buffer, 0, bytesRead)
            }
            bytesRead = input.read(buffer)
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun queryDisplayName(cursor: Cursor?): String? {
        cursor ?: return null
        cursor.use {
            if (!it.moveToFirst()) return null
            val nameIndex = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (nameIndex < 0) return null
            return it.getString(nameIndex)
        }
    }

    private fun humanFileSize(bytes: Long): String {
        if (bytes <= 0L) return "Unknown"
        val kb = 1024.0
        val mb = kb * 1024
        return when {
            bytes >= mb -> String.format(Locale.US, "%.1f MB", bytes / mb)
            bytes >= kb -> String.format(Locale.US, "%.1f KB", bytes / kb)
            else -> "$bytes B"
        }
    }

    private fun WifiNetwork.trustRank(): Int = when (level) {
        RiskLevel.High -> 0
        RiskLevel.Medium -> 1
        RiskLevel.Safe -> 2
    }

    private fun formatExpiry(isoDate: String): String {
        return runCatching {
            val expiry = OffsetDateTime.parse(isoDate)
            val hours = java.time.Duration.between(OffsetDateTime.now(), expiry).toHours().coerceAtLeast(0)
            "$hours hours"
        }.getOrDefault("24 hours")
    }

    private data class SafeBrowsingVerdict(
        val isThreat: Boolean,
        val summary: String
    )

    private data class VirusTotalVerdict(
        val malicious: Int,
        val suspicious: Int,
        val harmless: Int,
        val summary: String
    )
}
