from __future__ import annotations

import hashlib
import io
import logging
import os
import re
import zipfile
from datetime import datetime, timezone
from typing import Literal

import httpx
import xml.etree.ElementTree as ET

from .models import (
    ApkPermissionInfo,
    FileAnalysisResponse,
    VirusTotalStats,
)

# Configure logger for this module
logger = logging.getLogger("trustintel-backend.file_analysis")

# VirusTotal API configuration
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"

# Dangerous APK permissions and their risk levels
DANGEROUS_PERMISSIONS = {
    # SMS-related (HIGH risk - can intercept OTPs)
    "android.permission.READ_SMS": ("HIGH", "Can read all SMS messages including OTPs and verification codes."),
    "android.permission.SEND_SMS": ("HIGH", "Can send SMS messages without user knowledge, potentially incurring charges."),
    "android.permission.RECEIVE_SMS": ("HIGH", "Can receive and intercept incoming SMS messages."),
    "android.permission.RECEIVE_WAP_PUSH": ("MEDIUM", "Can receive WAP push messages, potentially malicious content."),
    "android.permission.RECEIVE_MMS": ("MEDIUM", "Can receive MMS messages without user interaction."),
    
    # Contact-related (HIGH risk - privacy invasion)
    "android.permission.READ_CONTACTS": ("HIGH", "Can read all contacts including names, phones, and emails."),
    "android.permission.WRITE_CONTACTS": ("MEDIUM", "Can modify or delete contacts without user knowledge."),
    
    # Call-related (HIGH risk)
    "android.permission.READ_CALL_LOG": ("HIGH", "Can read call history and phone numbers."),
    "android.permission.WRITE_CALL_LOG": ("MEDIUM", "Can modify or delete call history."),
    "android.permission.PROCESS_OUTGOING_CALLS": ("HIGH", "Can intercept and redirect outgoing calls."),
    
    # System overlay (HIGH risk - phishing)
    "android.permission.SYSTEM_ALERT_WINDOW": ("HIGH", "Can draw over other apps, commonly used in phishing overlay attacks."),
    
    # Package installation (HIGH risk)
    "android.permission.REQUEST_INSTALL_PACKAGES": ("HIGH", "Can install other apps without user going through Play Store."),
    
    # Settings modification
    "android.permission.WRITE_SETTINGS": ("MEDIUM", "Can modify system settings without user knowledge."),
    
    # Storage (MEDIUM risk)
    "android.permission.READ_EXTERNAL_STORAGE": ("MEDIUM", "Can read files from device storage."),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("MEDIUM", "Can write files to device storage."),
    
    # Camera and microphone
    "android.permission.CAMERA": ("MEDIUM", "Can take photos and videos without user knowledge."),
    "android.permission.RECORD_AUDIO": ("MEDIUM", "Can record audio without user knowledge."),
    
    # Location
    "android.permission.ACCESS_FINE_LOCATION": ("MEDIUM", "Can access precise GPS location."),
    "android.permission.ACCESS_COARSE_LOCATION": ("LOW", "Can access approximate location from network."),
    
    # Device admin
    "android.permission.DEVICE_POWER": ("HIGH", "Can control device power state."),
    "android.permission.BIND_DEVICE_ADMIN": ("HIGH", "Can gain device administrator privileges."),
    
    # Accessibility (HIGH risk - can control device)
    "android.permission.BIND_ACCESSIBILITY_SERVICE": ("HIGH", "Can monitor and control user interactions with the device."),
}

# Suspicious filename patterns
SUSPICIOUS_FILENAME_PATTERNS = [
    r"invoice.*\.(pdf|doc|xls|zip)",
    r"payment.*\.(pdf|doc|xls)",
    r"resume.*\.(doc|pdf|exe)",
    r"password.*\.(txt|doc|xls)",
    r"bank.*\.(pdf|doc|exe)",
    r"urgent.*\.(pdf|doc|exe)",
    r"verify.*\.(pdf|html|exe)",
    r"account.*suspended.*\.(pdf|html)",
]

# Phishing indicator keywords
PHISHING_KEYWORDS = [
    "verify your account",
    "suspended",
    "urgent action required",
    "click here immediately",
    "confirm your identity",
    "update payment",
    "verify login",
    "security alert",
]


def compute_sha256(file_content: bytes) -> str:
    """Compute SHA-256 hash of file content."""
    return hashlib.sha256(file_content).hexdigest()


def compute_sha256_from_stream(stream: io.BytesIO) -> str:
    """Compute SHA-256 hash from a byte stream."""
    sha256 = hashlib.sha256()
    while True:
        chunk = stream.read(8192)
        if not chunk:
            break
        sha256.update(chunk)
    return sha256.hexdigest()


def detect_file_type(filename: str, mime_type: str | None = None) -> str:
    """Detect file type from extension and MIME type."""
    ext = os.path.splitext(filename)[1].lower()
    
    type_mapping = {
        ".apk": "APK",
        ".exe": "Executable",
        ".dll": "DLL",
        ".pdf": "PDF",
        ".doc": "Word Document",
        ".docx": "Word Document",
        ".xls": "Excel Spreadsheet",
        ".xlsx": "Excel Spreadsheet",
        ".ppt": "PowerPoint",
        ".pptx": "PowerPoint",
        ".zip": "ZIP Archive",
        ".rar": "RAR Archive",
        ".7z": "7-Zip Archive",
        ".js": "JavaScript",
        ".vbs": "VBScript",
        ".bat": "Batch Script",
        ".ps1": "PowerShell Script",
        ".sh": "Shell Script",
        ".html": "HTML",
        ".htm": "HTML",
        ".xml": "XML",
        ".jar": "JAR Archive",
        ".dex": "DEX File",
    }
    
    if ext in type_mapping:
        return type_mapping[ext]
    
    if mime_type:
        if "apk" in mime_type:
            return "APK"
        if "pdf" in mime_type:
            return "PDF"
        if "zip" in mime_type:
            return "ZIP Archive"
        if "javascript" in mime_type:
            return "JavaScript"
        if "html" in mime_type:
            return "HTML"
    
    return ext.lstrip(".").upper() if ext else "Unknown"


def is_apk_file(filename: str, mime_type: str | None = None) -> bool:
    """Check if the file is an APK file."""
    if filename.lower().endswith(".apk"):
        return True
    if mime_type and "android.package-archive" in mime_type.lower():
        return True
    return False


def parse_apk_permissions(apk_content: bytes) -> list[ApkPermissionInfo]:
    """Parse APK file and extract permissions from AndroidManifest.xml."""
    permissions = []
    
    try:
        # Try to extract AndroidManifest.xml from APK (ZIP format)
        with zipfile.ZipFile(io.BytesIO(apk_content), 'r') as zf:
            # First try to find AndroidManifest.xml (in some APKs it might be uncompressed)
            manifest_names = [name for name in zf.namelist() 
                           if 'AndroidManifest' in name.lower()]
            
            if not manifest_names:
                logger.debug("No AndroidManifest.xml found in APK")
                return permissions
            
            # For binary XML, we would need axmlparser, but let's try to find
            # any text-based manifest first
            for manifest_name in manifest_names:
                try:
                    manifest_content = zf.read(manifest_name)
                    # Try to parse as text XML first
                    try:
                        text_content = manifest_content.decode('utf-8', errors='ignore')
                        if '<manifest' in text_content.lower():
                            perms = extract_permissions_from_xml(text_content)
                            permissions.extend(perms)
                            break
                    except (UnicodeDecodeError, ET.ParseError):
                        # Binary XML - we'll note this limitation
                        logger.debug(f"Found binary AndroidManifest.xml, text extraction limited")
                        # Look for permission strings in binary content
                        text_fragments = re.findall(
                            rb'android\.permission\.[A-Z_]+', manifest_content
                        )
                        for frag in text_fragments:
                            perm_name = frag.decode('utf-8')
                            if perm_name in DANGEROUS_PERMISSIONS:
                                risk, desc = DANGEROUS_PERMISSIONS[perm_name]
                                permissions.append(ApkPermissionInfo(
                                    name=perm_name.split('.')[-1],
                                    risk_level=risk,
                                    description=desc
                                ))
                except Exception as e:
                    logger.debug(f"Error parsing {manifest_name}: {e}")
                    continue
                    
    except zipfile.BadZipFile:
        logger.warning("File is not a valid ZIP (APK) file")
    except Exception as e:
        logger.error(f"Error parsing APK: {e}")
    
    return permissions


def extract_permissions_from_xml(xml_content: str) -> list[ApkPermissionInfo]:
    """Extract dangerous permissions from AndroidManifest.xml content."""
    permissions = []
    
    try:
        root = ET.fromstring(xml_content)
        # Find all uses-permission elements
        for elem in root.iter():
            if 'uses-permission' in elem.tag.lower():
                for attr_name, attr_value in elem.attrib.items():
                    if 'name' in attr_name.lower():
                        perm_name = attr_value
                        if perm_name in DANGEROUS_PERMISSIONS:
                            risk, desc = DANGEROUS_PERMISSIONS[perm_name]
                            permissions.append(ApkPermissionInfo(
                                name=perm_name.split('.')[-1],
                                risk_level=risk,
                                description=desc
                            ))
    except ET.ParseError:
        logger.debug("Could not parse XML, trying regex fallback")
        # Fallback to regex
        perm_matches = re.findall(r'android\.permission\.([A-Z_]+)', xml_content)
        for perm_suffix in perm_matches:
            full_name = f"android.permission.{perm_suffix}"
            if full_name in DANGEROUS_PERMISSIONS:
                risk, desc = DANGEROUS_PERMISSIONS[full_name]
                permissions.append(ApkPermissionInfo(
                    name=perm_suffix,
                    risk_level=risk,
                    description=desc
                ))
    
    return permissions


def check_suspicious_filename(filename: str) -> list[str]:
    """Check if filename matches suspicious patterns."""
    indicators = []
    filename_lower = filename.lower()
    
    for pattern in SUSPICIOUS_FILENAME_PATTERNS:
        if re.search(pattern, filename_lower):
            indicators.append(f"Filename matches suspicious pattern: {pattern}")
    
    return indicators


def check_phishing_indicators(filename: str, content_sample: str = "") -> list[str]:
    """Check for phishing indicators in filename and content."""
    indicators = []
    filename_lower = filename.lower()
    
    for keyword in PHISHING_KEYWORDS:
        if keyword in filename_lower:
            indicators.append(f"Phishing keyword in filename: '{keyword}'")
    
    if content_sample:
        content_lower = content_sample.lower()[:2000]  # Check first 2000 chars
        for keyword in PHISHING_KEYWORDS:
            if keyword in content_lower:
                indicators.append(f"Phishing keyword in content: '{keyword}'")
    
    return indicators


async def virustotal_file_lookup(sha256: str) -> dict | None:
    """Lookup file hash in VirusTotal database."""
    if not VIRUSTOTAL_API_KEY:
        logger.warning("VirusTotal API key not configured")
        return None
    
    url = f"{VIRUSTOTAL_BASE_URL}/files/{sha256}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, headers=headers)
            
            if response.status_code == 404:
                logger.info(f"File hash not found in VirusTotal: {sha256[:16]}...")
                return None
            
            if not response.is_success:
                logger.warning(f"VirusTotal API error: {response.status_code}")
                return None
            
            data = response.json()
            return data.get("data", {})
            
    except httpx.TimeoutException:
        logger.error("VirusTotal API timeout")
        return None
    except Exception as e:
        logger.error(f"VirusTotal lookup error: {e}")
        return None


async def virustotal_upload_file(file_content: bytes, filename: str) -> str | None:
    """Upload file to VirusTotal for analysis."""
    if not VIRUSTOTAL_API_KEY:
        logger.warning("VirusTotal API key not configured")
        return None
    
    url = f"{VIRUSTOTAL_BASE_URL}/files"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    try:
        # VirusTotal has a 32MB limit for direct uploads
        if len(file_content) > 32 * 1024 * 1024:
            logger.warning("File too large for VirusTotal upload (>32MB)")
            return None
        
        async with httpx.AsyncClient(timeout=60.0) as client:
            files = {"file": (filename, io.BytesIO(file_content), "application/octet-stream")}
            response = await client.post(url, headers=headers, files=files)
            
            if not response.is_success:
                logger.warning(f"VirusTotal upload failed: {response.status_code}")
                return None
            
            data = response.json()
            analysis_id = data.get("data", {}).get("id")
            logger.info(f"File uploaded to VirusTotal, analysis ID: {analysis_id}")
            return analysis_id
            
    except httpx.TimeoutException:
        logger.error("VirusTotal upload timeout")
        return None
    except Exception as e:
        logger.error(f"VirusTotal upload error: {e}")
        return None


async def virustotal_get_analysis(analysis_id: str) -> dict | None:
    """Get analysis results from VirusTotal."""
    if not VIRUSTOTAL_API_KEY:
        return None
    
    url = f"{VIRUSTOTAL_BASE_URL}/analyses/{analysis_id}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, headers=headers)
            
            if not response.is_success:
                return None
            
            return response.json().get("data", {})
            
    except Exception as e:
        logger.error(f"Error getting analysis: {e}")
        return None


def calculate_risk_score(
    vt_stats: VirusTotalStats | None = None,
    dangerous_perms: list[ApkPermissionInfo] | None = None,
    is_apk: bool = False,
    phishing_indicators: int = 0,
    suspicious_filename: bool = False,
) -> int:
    """Calculate overall risk score (0-100, higher is safer)."""
    score = 100
    
    # VirusTotal detections (major impact)
    if vt_stats:
        if vt_stats.malicious > 0:
            # -50 for any malicious detection, plus additional penalty
            score -= 50
            score -= min(vt_stats.malicious * 3, 30)  # Up to -30 more
        
        if vt_stats.suspicious > 0:
            score -= min(vt_stats.suspicious * 5, 20)  # Up to -20
    
    # Dangerous permissions
    if dangerous_perms:
        high_risk_count = sum(1 for p in dangerous_perms if p.risk_level == "HIGH")
        medium_risk_count = sum(1 for p in dangerous_perms if p.risk_level == "MEDIUM")
        score -= high_risk_count * 15
        score -= medium_risk_count * 8
    
    # Unsigned APK (we can't verify signatures easily, so we note this)
    if is_apk:
        score -= 5  # Minor penalty for being an APK
    
    # Phishing indicators
    score -= phishing_indicators * 10
    
    # Suspicious filename
    if suspicious_filename:
        score -= 15
    
    return max(0, min(100, score))


def score_to_level(score: int) -> Literal["SAFE", "MEDIUM", "HIGH"]:
    """Convert score to risk level."""
    if score >= 71:
        return "SAFE"
    elif score >= 41:
        return "MEDIUM"
    else:
        return "HIGH"


def generate_ai_explanation(
    filename: str,
    file_type: str,
    level: str,
    vt_stats: VirusTotalStats | None = None,
    permissions: list[ApkPermissionInfo] | None = None,
    phishing_indicators: list[str] | None = None,
) -> str:
    """Generate human-readable AI explanation of the threat analysis."""
    parts = []
    
    # Overall assessment
    if level == "HIGH":
        parts.append("⚠️ HIGH RISK detected. This file shows multiple indicators of malicious or suspicious behavior.")
    elif level == "MEDIUM":
        parts.append("⚡ MEDIUM RISK detected. Some concerning indicators were found that warrant caution.")
    else:
        parts.append("✓ LOW RISK. No significant threats detected in this file.")
    
    # VirusTotal findings
    if vt_stats and vt_stats.malicious > 0:
        parts.append(f"VirusTotal: {vt_stats.malicious}/{vt_stats.total_engines} security engines flagged this file as malicious.")
        if vt_stats.suspicious > 0:
            parts.append(f"Additionally, {vt_stats.suspicious} engines marked it as suspicious.")
    elif vt_stats:
        parts.append(f"VirusTotal: No malicious detections from {vt_stats.total_engines} security engines.")
    
    # APK-specific warnings
    if permissions:
        high_risk_perms = [p for p in permissions if p.risk_level == "HIGH"]
        if high_risk_perms:
            perm_names = ", ".join(p.name for p in high_risk_perms[:3])
            parts.append(f"Dangerous permissions detected: {perm_names}. These can be abused for phishing, SMS interception, or device control.")
    
    # Phishing warnings
    if phishing_indicators:
        parts.append(f"Phishing indicators found: {len(phishing_indicators)} suspicious patterns detected.")
    
    # File type specific
    if file_type == "APK":
        parts.append("APK files can contain malicious code that runs with app permissions. Always verify the source before installing.")
    elif file_type in ["Executable", "DLL"]:
        parts.append("Executable files can run arbitrary code on your system. Only run files from trusted sources.")
    elif file_type == "PDF":
        parts.append("PDF files can contain malicious scripts or exploits. Open only if you trust the sender.")
    
    return " ".join(parts)


def generate_recommendations(
    level: str,
    vt_stats: VirusTotalStats | None = None,
    permissions: list[ApkPermissionInfo] | None = None,
    is_apk: bool = False,
) -> list[str]:
    """Generate security recommendations based on analysis."""
    recommendations = []
    
    if level == "HIGH":
        recommendations.append("Do not open or install this file.")
        recommendations.append("Delete the file immediately from your device.")
        if vt_stats and vt_stats.malicious > 0:
            recommendations.append("Multiple security vendors have flagged this as malicious.")
        if is_apk:
            recommendations.append("Do not enable 'Install from Unknown Sources' for this app.")
        recommendations.append("If you already installed this, uninstall it immediately and run a full device scan.")
    elif level == "MEDIUM":
        recommendations.append("Exercise caution before opening this file.")
        recommendations.append("Verify the source and sender before proceeding.")
        if permissions:
            recommendations.append("Review the requested permissions carefully - some may be excessive.")
        recommendations.append("Consider using a sandboxed environment to open this file.")
    else:
        recommendations.append("File appears safe based on current analysis.")
        recommendations.append("Still verify the source before opening.")
        if is_apk:
            recommendations.append("Only install APKs from trusted sources like Google Play Store.")
    
    return recommendations


async def analyze_file(
    filename: str,
    file_content: bytes,
    mime_type: str | None = None,
    sha256: str | None = None,
) -> FileAnalysisResponse:
    """
    Main file analysis function that orchestrates all analysis steps.
    
    Returns a comprehensive FileAnalysisResponse with threat intelligence.
    """
    logger.info(f"Analyzing file: {filename} ({len(file_content)} bytes)")
    
    # Compute SHA-256 if not provided
    if not sha256:
        sha256 = compute_sha256(file_content)
    
    # Detect file type
    file_type = detect_file_type(filename, mime_type)
    is_apk = is_apk_file(filename, mime_type)
    
    # Initialize analysis results
    vt_stats = None
    malware_family = None
    threat_labels: list[str] = []
    permissions: list[ApkPermissionInfo] = []
    behavioral_findings: list[str] = []
    phishing_indicators_list: list[str] = []
    
    # Step 1: Check filename patterns
    suspicious_patterns = check_suspicious_filename(filename)
    behavioral_findings.extend(suspicious_patterns)
    
    # Step 2: VirusTotal lookup
    vt_data = await virustotal_file_lookup(sha256)
    
    if vt_data:
        attributes = vt_data.get("attributes", {})
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        
        vt_stats = VirusTotalStats(
            malicious=last_analysis_stats.get("malicious", 0),
            suspicious=last_analysis_stats.get("suspicious", 0),
            harmless=last_analysis_stats.get("harmless", 0),
            undetected=last_analysis_stats.get("undetected", 0),
            timeout=last_analysis_stats.get("timeout", 0),
            total_engines=last_analysis_stats.get("success", 0),
        )
        
        # Extract threat labels and malware family
        popular_threats = attributes.get("popular_threat_classification", {})
        if popular_threats:
            malware_family = popular_threats.get("suggested_threat_label")
            threat_labels = [t.get("value", "") for t in popular_threats.get("popular_threat_category", [])]
        
        behavioral_findings.append(f"VirusTotal analysis: {vt_stats.malicious} malicious, {vt_stats.suspicious} suspicious out of {vt_stats.total_engines} engines.")
    else:
        # File not found in VirusTotal - try uploading for analysis
        if VIRUSTOTAL_API_KEY and len(file_content) <= 32 * 1024 * 1024:
            logger.info("File not in VirusTotal database, uploading for analysis...")
            analysis_id = await virustotal_upload_file(file_content, filename)
            if analysis_id:
                behavioral_findings.append("File uploaded to VirusTotal for deeper analysis (new/unknown file).")
        else:
            behavioral_findings.append("File not found in VirusTotal database.")
    
    # Step 3: APK-specific analysis
    if is_apk:
        permissions = parse_apk_permissions(file_content)
        if permissions:
            high_risk = [p for p in permissions if p.risk_level == "HIGH"]
            if high_risk:
                behavioral_findings.append(f"Dangerous permissions detected: {len(high_risk)} high-risk permissions found.")
    
    # Step 4: Check for phishing indicators
    content_sample = ""
    try:
        # Sample first 4KB for text-based files
        content_sample = file_content[:4096].decode('utf-8', errors='ignore')
    except:
        pass
    
    phishing_indicators_list = check_phishing_indicators(filename, content_sample)
    
    # Step 5: Calculate risk score
    score = calculate_risk_score(
        vt_stats=vt_stats,
        dangerous_perms=permissions if permissions else None,
        is_apk=is_apk,
        phishing_indicators=len(phishing_indicators_list),
        suspicious_filename=len(suspicious_patterns) > 0,
    )
    
    level = score_to_level(score)
    
    # Step 6: Generate AI explanation and recommendations
    ai_explanation = generate_ai_explanation(
        filename=filename,
        file_type=file_type,
        level=level,
        vt_stats=vt_stats,
        permissions=permissions if permissions else None,
        phishing_indicators=phishing_indicators_list,
    )
    
    recommendations = generate_recommendations(
        level=level,
        vt_stats=vt_stats,
        permissions=permissions if permissions else None,
        is_apk=is_apk,
    )
    
    # Build response
    response = FileAnalysisResponse(
        filename=filename,
        file_type=file_type,
        file_size=len(file_content),
        sha256=sha256,
        trust_score=score,
        level=level,
        virustotal_stats=vt_stats,
        malware_family=malware_family,
        threat_labels=threat_labels,
        permissions=permissions,
        is_apk=is_apk,
        behavioral_findings=behavioral_findings[:5],  # Limit to 5 findings
        phishing_indicators=phishing_indicators_list,
        ai_explanation=ai_explanation,
        recommendations=recommendations,
        provider="virustotal" if VIRUSTOTAL_API_KEY else "backend-heuristics",
        analysis_timestamp=datetime.now(timezone.utc).isoformat(),
    )
    
    logger.info(f"File analysis complete: {filename} - Score: {score}, Level: {level}")
    return response


