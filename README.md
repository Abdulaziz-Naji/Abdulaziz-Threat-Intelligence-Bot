<div align="center">

# 🛡 Abdulaziz Threat Intelligence Bot

**A professional-grade Threat Intelligence Telegram Bot for SOC Analysts and Security Researchers.**

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Telegram](https://img.shields.io/badge/Telegram-Bot-blue?logo=telegram)](https://telegram.org/)
[![CI](https://github.com/Abdulaziz-Naji/Abdulaziz-threat-intelligence-bot/actions/workflows/ci.yml/badge.svg)](https://github.com/Abdulaziz-Naji/Abdulaziz-threat-intelligence-bot/actions)

[Telegram Demo](#-demo) · [Quick Start](#-quick-start) · [Deployment Guide](docs/DEPLOYMENT.md) · [Commands](#-commands)

</div>

---

## 📖 Overview

**Abdulaziz Threat Intelligence Bot** is a production-ready Telegram bot that aggregates threat intelligence from multiple sources and delivers professional, analyst-focused reports directly in Telegram.

Built for **SOC analysts, threat researchers, and cybersecurity professionals** who need fast, reliable IOC analysis without leaving their workflow.

### Why this bot?

- **Multi-source aggregation** — VirusTotal, AbuseIPDB, OTX, ThreatFox, URLHaus, MalwareBazaar, and more
- **Evidence-first reports** — Clean, compact output that shows only what matters
- **No noise** — Filters out low-confidence data, never shows internal API details
- **Full VT transparency** — Every flagging vendor shown, not just the first one
- **Autonomous DFIR** — Drag-and-drop files for instant forensic analysis
- **Case management** — Track and correlate multiple IOCs across investigations

---

## ✨ Features

| Category | Capability |
|----------|-----------|
| **IOC Intelligence** | IP, Domain, URL, File Hash analysis |
| **Email Intelligence** | MX/SPF/DMARC/DKIM validation + breach lookup |
| **Username OSINT** | 20 platforms across Social, Messaging, Gaming, Streaming |
| **DFIR Engine** | PE, PCAP, Office documents, images, archives |
| **Case Management** | Multi-IOC case tracking and correlation |
| **Watchlist** | Automated background monitoring with alerts |
| **Threat Feeds** | Auto-ingestion from ThreatFox, URLHaus, Feodo, CISA KEV |
| **CVE Lookup** | CVE details with CISA KEV tracking |
| **Threat News** | Curated cybersecurity news aggregation |
| **Threat Actors** | Actor database and attribution |

---

## 🎯 Supported IOC Types

| IOC Type | Example | Command |
|----------|---------|---------|
| IPv4 Address | `1.2.3.4` | `/check 1.2.3.4` |
| Domain | `malicious.com` | `/check malicious.com` |
| URL | `https://phishing.site/login` | `/check https://...` |
| MD5 Hash | `d41d8cd98f00b204...` | `/check d41d8cd...` |
| SHA1 Hash | `da39a3ee5e6b4b0d...` | `/check da39a3...` |
| SHA256 Hash | `e3b0c44298fc1c14...` | `/check e3b0c4...` |
| Email Address | `user@example.com` | `/email user@example.com` |
| Username | `john_doe` | `/username john_doe` |

---

## 🤖 Commands

### Core Intelligence
| Command | Description |
|---------|-------------|
| `/check <IOC>` | Full threat intelligence report for any IOC |
| `/brief <IOC>` | Quick one-line threat summary |
| `/email <address>` | Email intelligence — validation, breach lookup, provider |
| `/username <name>` | Cross-platform username OSINT (20 platforms) |
| `/phishing <url>` | Dedicated phishing analysis |

### DFIR & Files
| Command | Description |
|---------|-------------|
| `/dfir` (+ file) | Autonomous file forensics — PE, PCAP, Office, images, archives |
| `/file` (+ file) | Quick file hash + VirusTotal lookup |

### Threat Intelligence
| Command | Description |
|---------|-------------|
| `/feeds` | Latest threat intelligence feed updates |
| `/news` | Curated cybersecurity news |
| `/cve <ID>` | CVE details and CISA KEV status |
| `/actor <name>` | Threat actor profile |
| `/malware <family>` | Malware family intelligence |

### SOC & Case Management
| Command | Description |
|---------|-------------|
| `/case new <name>` | Create a new investigation case |
| `/case add <IOC>` | Add IOC to active case |
| `/case report` | Generate case report |
| `/soc` | SOC dashboard |

### Monitoring
| Command | Description |
|---------|-------------|
| `/watch <IOC>` | Add IOC to watchlist for monitoring |
| `/unwatch <IOC>` | Remove IOC from watchlist |
| `/watchlist` | View all monitored IOCs |
| `/monitor` | Monitoring status |

### Utility
| Command | Description |
|---------|-------------|
| `/start` | Introduction and help |
| `/history` | View recent queries |
| `/stats` | Bot statistics |

---

## ⚙️ Report Quality Standards

The bot follows strict report quality principles:

- ✅ **Show evidence only** — No low-confidence inferences
- ✅ **Full VT transparency** — All flagging vendors displayed
- ✅ **No internal API details** — No HTTP codes, API status messages
- ✅ **No stack traces** — Graceful error handling
- ✅ **Compact format** — Fits in a single Telegram screen

### Sample TI Report (IP)
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔍 Threat Intelligence Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

IOC        185.220.101.50
Type       IPv4 Address
ASN        AS205100 F3 Netze e.V.
Org        F3 Netze e.V.
Location   🇩🇪 Frankfurt | Germany
Infra      Hosting Provider

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 THREAT ASSESSMENT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Threat Score       85 / 100
Threat Level       🔴 Malicious
Classification     C2 Infrastructure | Tor Exit Node

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🛡 DETECTION SOURCES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VirusTotal     🔴 6 / 91

Summary
  Malicious    4
  Phishing     2

Detections
  • ADMINUSLabs    Malicious
  • BitDefender    Phishing
  • CRDF           Malicious
  • Fortinet       Malware
  • Sophos         Phishing
  • Webroot        Malicious

AbuseIPDB      🔴 97% confidence | 1,204 reports
GreyNoise      🔴 Malicious | Tor Exit Node
ThreatFox      🔴 Confirmed | botnet_cc | Mirai (90%)
```

---

## 🚀 Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/Abdulaziz-Naji/Abdulaziz-threat-intelligence-bot.git
cd Abdulaziz-threat-intelligence-bot

# 2. Install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Configure
cp .env.example .env
nano .env  # Add your API keys

# 4. Run
python main.py
```

---

## 🔧 Installation

### Requirements

- Python 3.11+
- A Telegram bot token (from [@BotFather](https://t.me/BotFather))
- API keys (see [Configuration](#configuration) below)

### Step-by-Step

```bash
# Clone
git clone https://github.com/Abdulaziz-Naji/Abdulaziz-threat-intelligence-bot.git
cd Abdulaziz-threat-intelligence-bot

# Virtual environment
python3 -m venv venv
source venv/bin/activate       # Linux/macOS
# venv\Scripts\activate        # Windows

# Install
pip install -r requirements.txt

# Configure
cp .env.example .env
```

---

## 🔑 Configuration

Edit `.env` with your credentials:

| Variable | Required | Description | Get it |
|----------|----------|-------------|--------|
| `TELEGRAM_BOT_TOKEN` | ✅ | Bot token | [@BotFather](https://t.me/BotFather) |
| `VT_API_KEY` | ✅ | VirusTotal API key | [virustotal.com](https://www.virustotal.com/gui/my-apikey) |
| `ABUSEIPDB_API_KEY` | ✅ | AbuseIPDB key | [abuseipdb.com](https://www.abuseipdb.com/register) |
| `OTX_API_KEY` | ✅ | AlienVault OTX | [otx.alienvault.com](https://otx.alienvault.com/api) |
| `ABUSE_CH_API_KEY` | ✅ | abuse.ch (ThreatFox, URLHaus, MalwareBazaar) | [abuse.ch](https://abuse.ch/) |
| `HIBP_API_KEY` | ⚙️ Optional | HaveIBeenPwned (breach lookup) | [haveibeenpwned.com](https://haveibeenpwned.com/API/Key) |
| `AUTHORIZED_USERS` | ⚙️ Optional | Restrict access to specific Telegram user IDs | Your Telegram user ID |
| `MONITOR_INTERVAL_MINUTES` | ⚙️ Optional | Watchlist check frequency (default: 60) | — |
| `FEED_CHECK_INTERVAL_MINUTES` | ⚙️ Optional | Feed pull frequency (default: 120) | — |

### Access Control

To restrict the bot to specific users:
```bash
AUTHORIZED_USERS=123456789,987654321
```

Leave empty to allow all users (open access).

---

## 📸 Screenshots

> *Screenshots coming soon*

---

## 🖥 Deployment (Ubuntu 24.04 / Oracle Cloud)

See the full guide: **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)**

Quick summary:

```bash
# Install as a systemd service
sudo cp docs/threat-intel-bot.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now threat-intel-bot

# View logs
sudo journalctl -u threat-intel-bot -f

# Update
git pull && pip install -r requirements.txt
sudo systemctl restart threat-intel-bot
```

---

## 🔒 Security

- **No API keys in code** — all secrets via `.env` (excluded from Git)
- **User authorization** — restrict access via `AUTHORIZED_USERS`
- **Graceful errors** — no stack traces or internal details shown to users
- **Database excluded** — `.gitignore` prevents database commits

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

---

## 🧪 Testing

```bash
# Run all verification tests
python tests/verify_phase15.py    # VT vendor transparency
python tests/verify_email_v2.py   # Email intelligence
python tests/verify_phase14.py    # Username OSINT
python tests/verify_phase12_1.py  # Classification engine
python tests/verify_threat_level.py  # Threat scoring
```

Tests run automatically on every push via [GitHub Actions](.github/workflows/ci.yml).

---

## 🏗 Architecture

```
threat-intel-bot/
├── main.py                  # Entry point
├── bot.py                   # Telegram bot setup
├── config.py                # Configuration
├── api_clients.py           # External API integrations
├── ti_report_builder.py     # TI report rendering engine
├── decision_engine.py       # IOC classification logic
├── ioc_risk_scoring.py      # Threat scoring engine
├── engine.py                # Core analysis orchestrator
├── handlers/                # Telegram command handlers
│   ├── check.py             # /check command
│   ├── email_cmd.py         # /email command
│   ├── username_cmd.py      # /username command
│   └── ...
├── feeds/                   # Threat feed integrations
│   ├── threatfox.py
│   ├── urlhaus.py
│   └── ...
└── tests/                   # Automated test suite
```

---

## 🤝 Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## ⚠️ Disclaimer

This tool is intended for **legitimate security research, threat analysis, and defensive purposes only**.

- All intelligence is sourced from public threat intelligence APIs
- The bot does not store personal data beyond analysis results
- Results reflect third-party API data — accuracy depends on source quality
- Not intended for offensive security operations

The author assumes no liability for misuse.

---

## 📬 Demo

> *Telegram demo link coming soon*

---

<div align="center">
Made with ❤️ for the security community
</div>
