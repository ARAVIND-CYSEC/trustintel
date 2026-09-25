package com.trustintel.app.data

import kotlinx.serialization.Serializable

@Serializable
data class ShareCreateApiResponse(
    val share_id: String,
    val file_name: String,
    val secure_url: String,
    val expires_at: String,
    val view_only: Boolean,
    val otp_enabled: Boolean,
    val revoked: Boolean
)

@Serializable
data class ShareAccessEventRequest(
    val action: String,
    val platform: String,
    val detail: String
)
