from __future__ import annotations

import logging
import os
from urllib.parse import urlparse

import httpx

from .models import UrlAnalyzeResponse

# Configure logger for this module
logger = logging.getLogger("trustintel-backend.threat_intel")

SAFE_BROWSING_KEY = os.getenv("SAFE_BROWSING_API_KEY", "").strip()


async def analyze_url(url: str) -> UrlAnalyzeResponse:
    normalized = normalize_url(url)
    logger.info(f"Analyzing URL: {normalized}")
    parsed = urlparse(normalized)

    findings: list[str] = []
    score = 88
    host = (parsed.hostname or "").lower()

    if parsed.scheme != "https":
        score -= 18
        findings.append("The site uses HTTP instead of HTTPS.")
    else:
        findings.append("HTTPS is enabled for the destination.")

    if host.replace(".", "").isdigit():
        score -= 20
        findings.append("The link points to a raw IP address instead of a normal domain.")

    if "xn--" in host:
        score -= 18
        findings.append("Punycode detected in the hostname, which can hide lookalike domains.")

    suspicious_keywords = ["login", "verify", "secure", "bank", "otp", "wallet", "update"]
    matched = next((key for key in suspicious_keywords if key in normalized.lower()), None)
    if matched:
        score -= 12
        findings.append(f"Suspicious keyword detected in the URL: {matched}.")

    host_parts = host.split(".")
    risky_tlds = {"xyz", "top", "click", "rest", "shop", "live"}
    if host_parts and host_parts[-1] in risky_tlds:
        score -= 12
        findings.append("The domain uses a high-abuse top-level domain.")

    redirects, status_code = await fetch_redirects(normalized)
    if redirects > 0:
        score -= redirects * 6
        findings.append(f"Live request observed {redirects} redirect step(s).")
    else:
        findings.append("No redirect chain was observed during live fetch.")
    if status_code is not None:
        findings.append(f"Live server response code: {status_code}.")
        if status_code >= 400:
            score -= 6

    provider = "backend-heuristics"
    provider_used = False

    if SAFE_BROWSING_KEY:
        provider = "google-safe-browsing"
        provider_used = True
        threat_summary = await safe_browsing_lookup(normalized)
        if threat_summary:
            score -= 42
            findings.append(f"Google Safe Browsing reported a threat match: {threat_summary}.")
        else:
            findings.append("Google Safe Browsing did not report a known threat.")
    else:
        findings.append("Google Safe Browsing key is missing on the backend, so only backend heuristics were used.")

    trust_score = max(8, min(96, score))
    level = score_to_level(trust_score)
    logger.info(f"URL analysis complete for {normalized}: score={trust_score}, level={level}")
    recommendation = {
        "HIGH": "Block this link and avoid entering passwords, OTPs, or payment details.",
        "MEDIUM": "Open only if you trust the sender. Use caution before logging in.",
        "SAFE": "No strong phishing signal detected in the live scan, but stay alert.",
    }[level]

    return UrlAnalyzeResponse(
        url=normalized,
        trust_score=trust_score,
        level=level,
        main_reason=findings[0] if findings else "Live scan completed.",
        findings=findings[:5],
        recommendation=recommendation,
        provider=provider,
        provider_used=provider_used,
    )


def normalize_url(url: str) -> str:
    trimmed = url.strip()
    if trimmed.startswith("http://") or trimmed.startswith("https://"):
        return trimmed
    return f"https://{trimmed}"


def score_to_level(score: int) -> str:
    if score >= 75:
        return "SAFE"
    if score >= 45:
        return "MEDIUM"
    return "HIGH"


async def fetch_redirects(url: str) -> tuple[int, int | None]:
    """Fetch URL and track redirect chain with timeout protection."""
    redirects = 0
    status_code: int | None = None
    current = url
    logger.debug(f"Fetching redirects for: {current}")
    async with httpx.AsyncClient(follow_redirects=False, timeout=10.0) as client:
        for _ in range(3):
            try:
                response = await client.get(current, headers={"User-Agent": "TrustIntel-Backend/1.0"})
                status_code = response.status_code
                if response.is_redirect and response.headers.get("location"):
                    redirects += 1
                    current = response.headers["location"]
                    logger.debug(f"Redirect #{redirects}: {current}")
                    continue
                break
            except httpx.TimeoutException as e:
                logger.warning(f"Timeout while fetching {current}: {e}")
                break
            except httpx.ConnectError as e:
                logger.warning(f"Connection error while fetching {current}: {e}")
                break
            except Exception as e:
                logger.warning(f"Error while fetching {current}: {e}")
                break
    return redirects, status_code


async def safe_browsing_lookup(url: str) -> str | None:
    """Lookup URL in Google Safe Browsing API with error handling."""
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_KEY}"
    payload = {
        "client": {"clientId": "trustintel-backend", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    logger.debug(f"Querying Google Safe Browsing for: {url}")
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.post(endpoint, json=payload)
            if not response.is_success:
                logger.warning(f"Safe Browsing API returned status {response.status_code}")
                return None
            body = response.json()
            matches = body.get("matches", [])
            if not matches:
                logger.debug("No threats found in Safe Browsing")
                return None
            threat_types = ", ".join(match.get("threatType", "UNKNOWN") for match in matches)
            logger.info(f"Safe Browsing found threats: {threat_types}")
            return threat_types
        except httpx.TimeoutException as e:
            logger.error(f"Timeout querying Safe Browsing API: {e}")
            return None
        except httpx.ConnectError as e:
            logger.error(f"Cannot connect to Safe Browsing API: {e}")
            return None
        except Exception as e:
            logger.error(f"Error querying Safe Browsing API: {e}")
            return None
