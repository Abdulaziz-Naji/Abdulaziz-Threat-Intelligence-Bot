# Deployment Guide — Ubuntu 24.04 (Oracle Cloud)

This guide covers installing and running the bot on a fresh **Ubuntu 24.04** server,
including Oracle Cloud Free Tier instances.

---

## Prerequisites

- Ubuntu 24.04 LTS server
- Root or sudo access
- A Telegram bot token from [@BotFather](https://t.me/BotFather)
- API keys for VirusTotal, AbuseIPDB, OTX, and abuse.ch

---

## 1. System Preparation

```bash
sudo apt update && sudo apt upgrade -y

sudo apt install -y \
    python3.11 \
    python3.11-venv \
    python3-pip \
    git \
    curl \
    unzip \
    libffi-dev \
    libssl-dev \
    build-essential
```

---

## 2. Clone the Repository

```bash
sudo mkdir -p /opt/threat-intel-bot
sudo chown ubuntu:ubuntu /opt/threat-intel-bot

git clone https://github.com/Abdulaziz-Naji/Abdulaziz-threat-intelligence-bot.git /opt/threat-intel-bot
cd /opt/threat-intel-bot
```

---

## 3. Python Virtual Environment

```bash
python3.11 -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
```

---

## 4. Configure Environment Variables

```bash
cp .env.example .env
nano .env
```

Fill in all required values:

| Variable | Description |
|----------|-------------|
| `TELEGRAM_BOT_TOKEN` | From @BotFather |
| `VT_API_KEY` | VirusTotal API key |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key |
| `OTX_API_KEY` | AlienVault OTX key |
| `ABUSE_CH_API_KEY` | abuse.ch API key |
| `HIBP_API_KEY` | HaveIBeenPwned key (optional) |
| `AUTHORIZED_USERS` | Comma-separated Telegram user IDs |
| `MONITOR_INTERVAL_MINUTES` | Watchlist check interval (default: 60) |
| `FEED_CHECK_INTERVAL_MINUTES` | Feed pull interval (default: 120) |

```bash
# Protect the .env file
chmod 600 .env
```

---

## 5. Test Run (Manual)

Before installing as a service, verify the bot starts correctly:

```bash
source venv/bin/activate
python main.py
```

You should see:
```
[INFO] Bot started. Listening for messages...
```

Press `Ctrl+C` to stop, then proceed to the service setup.

---

## 6. Install as a Systemd Service

```bash
# Copy the service file
sudo cp docs/threat-intel-bot.service /etc/systemd/system/

# Reload systemd and enable the service
sudo systemctl daemon-reload
sudo systemctl enable threat-intel-bot
sudo systemctl start threat-intel-bot
```

---

## 7. Service Management

```bash
# Check status
sudo systemctl status threat-intel-bot

# View live logs
sudo journalctl -u threat-intel-bot -f

# View last 100 lines
sudo journalctl -u threat-intel-bot -n 100

# Restart
sudo systemctl restart threat-intel-bot

# Stop
sudo systemctl stop threat-intel-bot
```

---

## 8. Update Workflow

```bash
cd /opt/threat-intel-bot

# Pull latest changes
git pull origin main

# Install any new dependencies
source venv/bin/activate
pip install -r requirements.txt

# Restart the service
sudo systemctl restart threat-intel-bot

# Verify it's running
sudo systemctl status threat-intel-bot
```

---

## 9. Oracle Cloud Firewall Notes

Oracle Cloud instances have an additional firewall layer (iptables) beyond the Security List.
The bot only needs outbound internet access (no inbound ports required).

If you see connection issues, verify outbound HTTPS (443) is allowed:

```bash
sudo iptables -L OUTPUT -n | grep ACCEPT
```

---

## 10. Troubleshooting

### Bot doesn't respond
1. Check service status: `sudo systemctl status threat-intel-bot`
2. Check logs: `sudo journalctl -u threat-intel-bot -n 50`
3. Verify `.env` has a valid `TELEGRAM_BOT_TOKEN`
4. Test manually: `cd /opt/threat-intel-bot && source venv/bin/activate && python main.py`

### API errors
- Verify API keys are correct in `.env`
- Check API rate limits (VirusTotal: 500/day on free tier)
- The bot gracefully degrades — if one API fails, others still work

### Database issues
```bash
# The database is auto-created on first run
ls -la /opt/threat-intel-bot/*.db
```

---

## File Permissions Summary

```bash
# Project directory
chmod 755 /opt/threat-intel-bot

# Environment file (secrets — must be restricted)
chmod 600 /opt/threat-intel-bot/.env

# Database (auto-managed)
chmod 644 /opt/threat-intel-bot/threat_intel.db
```
