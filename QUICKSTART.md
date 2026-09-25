# TrustIntel Quick Start Guide

Get the TrustIntel platform running in 5 minutes!

## Prerequisites

- **Python 3.8+** (for backend)
- **Android Studio** (for Android app)
- **Android SDK** (API level 35)
- **API Keys** (optional, for full functionality):
  - Google Safe Browsing API key
  - VirusTotal API key

## Step-by-Step Setup

### 1. Start the Backend Server

Open a terminal and run:

```bash
# Navigate to backend directory
cd backend

# Create and activate virtual environment
python -m venv .venv

# Windows:
.venv\Scripts\activate

# Mac/Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set API keys (optional but recommended)
# Windows (PowerShell):
$env:SAFE_BROWSING_API_KEY="your_key_here"
$env:VIRUSTOTAL_API_KEY="your_key_here"

# Mac/Linux:
export SAFE_BROWSING_API_KEY="your_key_here"
export VIRUSTOTAL_API_KEY="your_key_here"

# Start the server (IMPORTANT: use --host 0.0.0.0)
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

**Expected output:**
```
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
INFO:     Application startup complete.
```

✅ **Keep this terminal open** - the backend needs to stay running.

### 2. Configure the Android App

In a **new terminal** (keep the backend running!), navigate to the project root:

```bash
# Verify local.properties has the correct backend URL
# For emulator:
# SECURE_SHARE_BASE_URL=http://10.0.2.2:8000

# For physical device, replace with your computer's IP:
# SECURE_SHARE_BASE_URL=http://192.168.1.XXX:8000
```

The `local.properties` file should already contain:
```properties
SECURE_SHARE_BASE_URL=http://10.0.2.2:8000
SAFE_BROWSING_API_KEY=019d7d16-b4b4-777a-bbf2-a8840bc135a2
VIRUSTOTAL_API_KEY=25ef8979da2cceb3b7d6998b6a7b6400a3994ac5419b7289c4c9dd043e300732
```

### 3. Build and Run the Android App

```bash
# Clean and build the project
./gradlew clean build

# Or open in Android Studio:
# File -> Open -> select the project root
# Then click the Run button (green play icon)
```

### 4. Test the Connection

Once the Android app is running:

1. **Test URL Analysis:**
   - Go to the "Scan" tab
   - Enter a URL (e.g., `https://example.com`)
   - Tap "Run Scan"
   - You should see analysis results

2. **Check Backend Logs:**
   In the backend terminal, you should see:
   ```
   INFO - Incoming request: POST /analyze/url from 10.0.2.2
   INFO - Analyzing URL: https://example.com
   INFO - URL analysis complete: score=88, level=SAFE
   INFO - Response: POST /analyze/url - Status: 200 - Time: 1.234s
   ```

## Troubleshooting

### Backend won't start

**Error:** `Port 8000 is already in use`

**Solution:** Use a different port:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
```
Then update `local.properties`:
```properties
SECURE_SHARE_BASE_URL=http://10.0.2.2:8001
```

### Android app can't connect to backend

**Error:** `Connection refused` or `Failed to connect to /10.0.2.2:8000`

**Solutions:**

1. **Verify backend is running:**
   ```bash
   curl http://localhost:8000/health
   ```
   Should return: `{"status":"ok","timestamp":...,"version":"0.1.0","service":"TrustIntel Secure Share API"}`

2. **Check backend is bound to 0.0.0.0:**
   ```bash
   # Windows:
   netstat -an | findstr :8000
   
   # Mac/Linux:
   lsof -i :8000
   ```
   Look for `0.0.0.0:8000` or `*:8000`, NOT `127.0.0.1:8000`

3. **Restart backend with correct host:**
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

4. **Check Windows Firewall:**
   - Open Windows Defender Firewall
   - Advanced settings -> Inbound Rules
   - Create new rule allowing TCP port 8000

### Using a physical Android device

1. **Find your computer's IP address:**
   ```bash
   # Windows:
   ipconfig
   # Look for "IPv4 Address" under your network adapter
   
   # Mac/Linux:
   ifconfig
   # Look for "inet" under your active interface
   ```

2. **Update local.properties:**
   ```properties
   SECURE_SHARE_BASE_URL=http://YOUR_IP_ADDRESS:8000
   ```

3. **Ensure device and computer are on the same WiFi network**

4. **Rebuild the app:**
   ```bash
   ./gradlew clean build
   ```

## Testing Specific Features

### Test URL Analysis via curl
```bash
curl -X POST http://localhost:8000/analyze/url \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

### Test File Sharing via curl
```bash
curl -X POST http://localhost:8000/shares \
  -F "file=@/path/to/file.pdf" \
  -F "expires_hours=24" \
  -F "view_only=true" \
  -F "otp_enabled=true"
```

### Test File Analysis via curl
```bash
# Analyze any file (APK, PDF, EXE, etc.)
curl -X POST http://localhost:8000/analyze/file \
  -F "file=@/path/to/file.apk"

# Example response includes:
# - trust_score: 0-100 (higher is safer)
# - level: SAFE, MEDIUM, or HIGH
# - virustotal_stats: Malware detection counts
# - permissions: Dangerous APK permissions
# - ai_explanation: Human-readable threat analysis
# - recommendations: Security action items
```

### Test File Analysis with VirusTotal
For full malware intelligence, set your VirusTotal API key:

```bash
# Set API key before starting backend
export VIRUSTOTAL_API_KEY="your_virustotal_key"

# Then start backend and test
curl -X POST http://localhost:8000/analyze/file \
  -F "file=@/path/to/suspicious_file.exe"
```

### Test Health Endpoint
```bash
curl http://localhost:8000/health
```

## Viewing Logs

### Backend Logs
The backend terminal shows all activity:
- Request/response logging
- URL analysis details
- Errors and warnings
- Performance metrics

### Android Logs
```bash
# View all logs
adb logcat

# Filter by tag
adb logcat -s TrustIntel

# Clear logs
adb logcat -c
```

## Next Steps

1. **Explore the app features:**
   - Home: Security status and quick actions
   - Scan: URL and file analysis
   - Share: Secure file sharing
   - WiFi: Network security scanning
   - Profile: Usage statistics

2. **Read the detailed documentation:**
   - `BACKEND_SETUP.md` - Comprehensive backend setup and troubleshooting
   - `README.md` - Project overview and architecture

3. **Customize the app:**
   - Add your own API keys
   - Modify the UI theme in `app/src/main/java/com/trustintel/app/ui/theme/`
   - Extend backend functionality in `backend/app/`

## Common Commands

```bash
# Backend
cd backend
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Mac/Linux
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Android
./gradlew clean build
./gradlew installDebug  # Install on connected device
adb logcat  # View logs

# Testing
curl http://localhost:8000/health
```

## Need Help?

- Check `BACKEND_SETUP.md` for detailed troubleshooting
- Review backend logs for error messages
- Test endpoints with curl or Postman
- Use `adb logcat` to debug Android issues

---

**That's it!** You should now have a fully functional TrustIntel platform running locally. 🚀