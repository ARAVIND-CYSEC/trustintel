# TrustIntel Android MVP

Native Android MVP for the "Mobile Trust Intelligence Platform" concept, built with Kotlin and Jetpack Compose.

## What is included

- Five-tab app shell: `Home`, `Scan`, `Share`, `WiFi`, `Profile`
- Dark cyber-inspired UI with glass-like cards and compact mobile layouts
- Share-sheet entry handling for shared URLs and files
- Unified trust-intelligence domain layer for URL, file, sharing, and WiFi workflows
- Real local URL/WiFi/file analysis plus optional live reputation integrations

## Product mapping

- `Home`: security status, quick actions, recent activity
- `Scan`: URL trust analysis, shared file findings, AI-friendly explanations
- `Share`: protected-link generation and access timeline
- `WiFi`: nearby network risk labels and sensitive-action warnings
- `Profile`: operational metrics and intelligence refresh

## Key files

- `app/src/main/java/com/trustintel/app/MainActivity.kt`
- `app/src/main/java/com/trustintel/app/ui/TrustIntelApp.kt`
- `app/src/main/java/com/trustintel/app/ui/TrustIntelViewModel.kt`
- `app/src/main/java/com/trustintel/app/data/TrustIntelRepository.kt`

## Next implementation steps

1. Add API keys in `local.properties`:
   `SAFE_BROWSING_API_KEY=...`
   `VIRUSTOTAL_API_KEY=...`
   `SECURE_SHARE_BASE_URL=...`
2. Add a backend for secure sharing, WHOIS/domain age, and deep document malware analysis.
3. Add Room caching, encrypted local storage, and background jobs for deep scans.
4. Replace placeholder icon/theme assets with branded resources and production-safe launcher icons.

## Build note

This repo contains the Android source scaffold, but the Gradle wrapper files are not included yet. Open the project in Android Studio or add a wrapper with `gradle wrapper` in a machine that has Gradle installed.
