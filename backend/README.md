# TrustIntel Secure Share Backend

FastAPI scaffold for the secure file sharing module.

## Run

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Endpoints

- `GET /health`
- `POST /analyze/url` - URL phishing/malware analysis
- `POST /analyze/file` - File malware analysis with VirusTotal integration
  - Accepts multipart form with `file` field
  - Returns comprehensive threat intelligence report
  - Supports APK permission analysis
- `POST /shares`
  - multipart form fields:
    - `file`
    - `expires_hours`
    - `view_only`
    - `otp_enabled`
- `GET /shares/{share_id}`
- `POST /shares/{share_id}/events`
- `POST /shares/{share_id}/revoke`
- `POST /shares/{share_id}/otp/verify`

## Notes

- This scaffold uses local disk storage under `backend/storage/`
- Metadata and access logs are stored in memory for now
- Replace the repository with PostgreSQL and the storage layer with S3/R2 for production
- To enable Google Safe Browsing in the backend, set environment variable:
  `SAFE_BROWSING_API_KEY=your_key`
- To enable VirusTotal file analysis, set environment variable:
  `VIRUSTOTAL_API_KEY=your_key`

## File Analysis Features

The `/analyze/file` endpoint provides:

1. **SHA-256 Hash Generation** - Compute file hash for reputation lookup
2. **VirusTotal Integration** - Query 70+ security engines for malware detection
3. **APK Permission Analysis** - Parse Android manifests for dangerous permissions
4. **Risk Scoring** - Calculate 0-100 safety score with HIGH/MEDIUM/SAFE levels
5. **Phishing Detection** - Analyze filenames and content for phishing indicators
6. **AI Explanation** - Generate human-readable threat explanations
7. **Recommendations** - Provide actionable security recommendations

### Risk Score Thresholds

| Score Range | Risk Level |
|-------------|------------|
| 71-100      | SAFE       |
| 41-70       | MEDIUM     |
| 0-40        | HIGH       |
