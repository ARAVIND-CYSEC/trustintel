# TrustIntel Backend Setup & Troubleshooting Guide

This guide covers how to set up, run, and troubleshoot the TrustIntel backend API for connectivity with the Android app.

## Quick Start

### 1. Set Up Python Environment

```bash
cd backend

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# Mac/Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment Variables

Set your API keys as environment variables:

**Windows (Command Prompt):**
```cmd
set SAFE_BROWSING_API_KEY=your_google_safe_browsing_key
set VIRUSTOTAL_API_KEY=your_virustotal_key
```

**Windows (PowerShell):**
```powershell
$env:SAFE_BROWSING_API_KEY="your_google_safe_browsing_key"
$env:VIRUSTOTAL_API_KEY="your_virustotal_key"
```

**Mac/Linux:**
```bash
export SAFE_BROWSING_API_KEY="your_google_safe_browsing_key"
export VIRUSTOTAL_API_KEY="your_virustotal_key"
```

### 3. Start the Backend Server

**Important:** Use `--host 0.0.0.0` to make the server accessible from outside localhost:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

You should see output like:
```
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
INFO:     Started reloader process [12345]
INFO:     Started server process [67890]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
```

### 4. Verify Backend is Running

Open a new terminal and test the health endpoint:

```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "ok",
  "timestamp": 1234567890.123,
  "version": "0.1.0",
  "service": "TrustIntel Secure Share API"
}
```

## Android App Configuration

### For Android Emulator

The emulator uses `10.0.2.2` to access the host machine's localhost. Update `local.properties` in the project root:

```properties
SECURE_SHARE_BASE_URL=http://10.0.2.2:8000
```

### For Physical Android Device

1. Find your computer's local IP address:
   - **Windows:** Run `ipconfig` and look for "IPv4 Address"
   - **Mac/Linux:** Run `ifconfig` and look for "inet" under your active interface

2. Update `local.properties`:
   ```properties
   SECURE_SHARE_BASE_URL=http://YOUR_COMPUTER_IP:8000
   ```

3. Ensure your device and computer are on the same WiFi network.

4. Rebuild the Android app:
   ```bash
   ./gradlew clean build
   ```

## Troubleshooting Connectivity Issues

### Issue 1: "Connection refused" or "Failed to connect to /10.0.2.2:8000"

**Causes:**
- Backend server is not running
- Backend is running on `127.0.0.1` instead of `0.0.0.0`
- Firewall is blocking port 8000

**Solutions:**

1. Verify the backend is running:
   ```bash
   curl http://localhost:8000/health
   ```

2. Check that it's bound to `0.0.0.0`:
   ```bash
   # Windows
   netstat -an | findstr :8000
   
   # Mac/Linux
   lsof -i :8000
   ```
   You should see `0.0.0.0:8000` or `*:8000`, not `127.0.0.1:8000`

3. If running on `127.0.0.1`, restart with:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

4. Check Windows Firewall (if applicable):
   - Open Windows Defender Firewall
   - Click "Advanced settings"
   - Create a new inbound rule allowing TCP port 8000

### Issue 2: CORS Errors

**Symptoms:**
- Browser console shows CORS errors (if testing via web)
- Android app receives network errors

**Solution:**
CORS is already configured in `backend/app/main.py`. If you still see issues, verify the middleware is in place:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Issue 3: Timeout Errors

**Symptoms:**
- Requests take too long and fail
- "Socket timeout" errors in logs

**Solutions:**

1. The Android client now has 30-second timeouts configured in `TrustIntelRepository.kt`:
   ```kotlin
   private val httpClient = OkHttpClient.Builder()
       .connectTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
       .readTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
       .writeTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
       .retryOnConnectionFailure(true)
       .build()
   ```

2. Check your network connection speed.

3. For slow external API calls (VirusTotal, Google Safe Browsing), consider increasing timeouts in `threat_intel.py`.

### Issue 4: Cleartext HTTP Not Allowed

**Symptoms:**
- Android logs show "Cleartext HTTP traffic not permitted"

**Solution:**
The AndroidManifest.xml already has `android:usesCleartextTraffic="true"`. If you still see this error, verify the manifest is being used and rebuild the app.

## Testing the Backend API

### Test URL Analysis

```bash
curl -X POST http://localhost:8000/analyze/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### Test File Upload

```bash
curl -X POST http://localhost:8000/shares \
  -F "file=@/path/to/your/file.pdf" \
  -F "expires_hours=24" \
  -F "view_only=true" \
  -F "otp_enabled=true"
```

### Test Health Endpoint

```bash
curl http://localhost:8000/health
```

## Viewing Logs

The backend now has comprehensive logging. When running, you'll see:

- **INFO level:** Request/response logging, URL analysis results
- **DEBUG level:** Detailed API calls, redirect tracking
- **WARNING level:** Timeouts, connection issues
- **ERROR level:** Unhandled exceptions, API failures

Example log output:
```
2026-05-16 11:30:00,000 - trustintel-backend - INFO - Incoming request: POST /analyze/url from 10.0.2.2
2026-05-16 11:30:00,100 - trustintel-backend.threat_intel - INFO - Analyzing URL: https://example.com
2026-05-16 11:30:01,500 - trustintel-backend.threat_intel - INFO - URL analysis complete: score=88, level=SAFE
2026-05-16 11:30:01,501 - trustintel-backend - INFO - Response: POST /analyze/url - Status: 200 - Time: 1.501s
```

## API Endpoints Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check with version info |
| POST | `/analyze/url` | Analyze a URL for threats |
| POST | `/shares` | Create a secure file share |
| GET | `/shares/{share_id}` | Get share details and access log |
| POST | `/shares/{share_id}/events` | Log an access event |
| POST | `/shares/{share_id}/revoke` | Revoke a share |
| POST | `/shares/{share_id}/otp/verify` | Verify OTP for share access |

## Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| Backend won't start | Check Python version (3.8+), verify virtual environment is activated |
| Port 8000 already in use | Change port: `--port 8001` and update `local.properties` |
| API keys not working | Verify keys are set as environment variables, check key validity |
| Slow performance | Check network speed, consider caching, optimize external API calls |
| File uploads fail | Check disk space, verify file size limits, check permissions |

## Production Considerations

For production deployment, consider:

1. **Use HTTPS:** Configure SSL/TLS with a reverse proxy (nginx, Caddy)
2. **Database:** Replace in-memory storage with PostgreSQL/MySQL
3. **File Storage:** Use S3, Google Cloud Storage, or Azure Blob Storage
4. **Authentication:** Add API key or JWT authentication
5. **Rate Limiting:** Implement rate limiting to prevent abuse
6. **Monitoring:** Add health checks, metrics, and alerting
7. **Environment Config:** Use `.env` file or config management service

## Getting Help

If you encounter issues not covered in this guide:

1. Check the backend logs for error messages
2. Verify all environment variables are set correctly
3. Test endpoints directly with `curl` or Postman
4. Ensure your network allows traffic on port 8000
5. Review the Android app logs via `adb logcat`

## Summary of Changes Made

The following improvements were implemented to resolve backend connectivity issues:

### Android Client (`TrustIntelRepository.kt`)
- ✅ Added 30-second timeouts for connect, read, and write operations
- ✅ Enabled retry on connection failure
- ✅ Improved error messages for debugging

### Backend (`main.py`)
- ✅ Added comprehensive request/response logging middleware
- ✅ Added global exception handler with detailed error responses
- ✅ Enhanced health endpoint with version and timestamp info
- ✅ Added structured logging throughout

### Backend (`threat_intel.py`)
- ✅ Added detailed logging for URL analysis
- ✅ Added timeout and connection error handling
- ✅ Improved error messages for external API calls
- ✅ Added debug logging for redirect tracking

### Configuration
- ✅ Verified `android:usesCleartextTraffic="true"` in AndroidManifest.xml
- ✅ Confirmed CORS middleware is properly configured
- ✅ Documented proper server startup with `--host 0.0.0.0`