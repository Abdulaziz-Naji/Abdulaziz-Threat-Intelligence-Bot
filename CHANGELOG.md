# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2025-07-01

### Added
- **Core TI Engine** — Multi-source threat intelligence reports for IPs, domains, URLs, and hashes
- **VirusTotal Integration** — Full vendor detection table with summary and per-vendor labels
- **AbuseIPDB Integration** — IP reputation and abuse confidence scoring
- **AlienVault OTX** — Pulse references (informational only, no scoring)
- **ThreatFox / URLHaus / MalwareBazaar** — Authoritative feed classifications
- **GreyNoise** — Internet scanner and noise classification
- **Email Intelligence** (`/email`) — MX, SPF, DMARC, DKIM, Catch-All, Disposable detection + breach lookup
- **Username OSINT** (`/username`) — Cross-platform identity search across 20 platforms
- **DFIR Engine** — Autonomous file forensics for PE, PCAP, Office, images, archives
- **Case Management** — Create, manage, and correlate investigation cases
- **Watchlist Monitoring** — Automatic background monitoring with alerts
- **Threat Feeds** — Automatic threat intelligence feed ingestion
- **CVE Lookup** — CVE details and CISA KEV tracking
- **Threat News** — Curated cybersecurity news aggregation
- **Phishing Analysis** — Dedicated phishing detection engine
- **Malware Intelligence** — Malware family and behavior analysis
- **Threat Actors** — Threat actor database and attribution

### Security
- No API keys stored in repository
- User authorization via `AUTHORIZED_USERS` environment variable
- All secrets loaded exclusively from `.env`

### Report Quality
- Phase 13: Simplified reports — removed noise, kept evidence only
- Phase 13.1: OTX scoring redesign — OTX no longer inflates threat score
- Phase 13.2: Compact DNS rendering
- Phase 14: Username OSINT redesign — 20 curated platforms
- Phase 15: Full VT vendor transparency — all detections displayed

---

[1.0.0]: https://github.com/Abdulaziz-Naji/Abdulaziz-threat-intelligence-bot/releases/tag/v1.0.0
