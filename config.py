"""
config.py - Configuration loader
Loads all environment variables and validates required keys.
"""
import os
from dotenv import load_dotenv

load_dotenv()

# ─── Telegram ─────────────────────────────────────────────────────────────────
TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "")

# ─── Primary API Keys ─────────────────────────────────────────────────────────
VT_API_KEY: str        = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY: str       = os.getenv("OTX_API_KEY", "")

# ─── Optional Enrichment Keys ─────────────────────────────────────────────────
SHODAN_API_KEY: str    = os.getenv("SHODAN_API_KEY", "")
GREYNOISE_API_KEY: str = os.getenv("GREYNOISE_API_KEY", "")
PHISHTANK_API_KEY: str = os.getenv("PHISHTANK_API_KEY", "")
ABUSE_CH_API_KEY: str  = os.getenv("ABUSE_CH_API_KEY", "")


# ─── Feed Polling Intervals (seconds) ─────────────────────────────────────────
INTERVAL_MALWAREBAZAAR: int = int(os.getenv("INTERVAL_MALWAREBAZAAR", str(30 * 60)))
INTERVAL_URLHAUS: int       = int(os.getenv("INTERVAL_URLHAUS",       str(30 * 60)))
INTERVAL_THREATFOX: int     = int(os.getenv("INTERVAL_THREATFOX",     str(30 * 60)))
INTERVAL_OPENPHISH: int     = int(os.getenv("INTERVAL_OPENPHISH",     str(60 * 60)))
INTERVAL_OTX: int           = int(os.getenv("INTERVAL_OTX",           str(60 * 60)))
INTERVAL_FEODO: int         = int(os.getenv("INTERVAL_FEODO",         str(60 * 60)))
INTERVAL_ABUSEIPDB: int     = int(os.getenv("INTERVAL_ABUSEIPDB",     str(6 * 60 * 60)))
INTERVAL_CISA_KEV: int      = int(os.getenv("INTERVAL_CISA_KEV",      str(12 * 60 * 60)))
INTERVAL_CIRCL_CVE: int     = int(os.getenv("INTERVAL_CIRCL_CVE",     str(12 * 60 * 60)))

# ─── Watchlist Monitor Interval ───────────────────────────────────────────────
MONITOR_INTERVAL_MINUTES: int    = int(os.getenv("MONITOR_INTERVAL_MINUTES",    "60"))
FEED_CHECK_INTERVAL_MINUTES: int = int(os.getenv("FEED_CHECK_INTERVAL_MINUTES", "30"))

# ─── Report Schedule ──────────────────────────────────────────────────────────
DAILY_REPORT_HOUR: int   = int(os.getenv("DAILY_REPORT_HOUR",   "8"))   # 08:00 UTC
WEEKLY_REPORT_WEEKDAY: int = int(os.getenv("WEEKLY_REPORT_WEEKDAY", "0")) # Monday=0

# ─── Access Control ───────────────────────────────────────────────────────────
_auth_raw: str = os.getenv("AUTHORIZED_USERS", "")
AUTHORIZED_USERS: list[int] = (
    [int(uid.strip()) for uid in _auth_raw.split(",") if uid.strip()]
    if _auth_raw.strip()
    else []
)

# ─── Database ─────────────────────────────────────────────────────────────────
DB_PATH: str = os.path.join(os.path.dirname(__file__), "threat_intel.db")
MAX_FILE_SIZE_MB: int = int(os.getenv("MAX_FILE_SIZE_MB", "20"))

# ─── Validation ───────────────────────────────────────────────────────────────
REQUIRED = {"TELEGRAM_BOT_TOKEN": TELEGRAM_BOT_TOKEN}

def validate():
    missing = [k for k, v in REQUIRED.items() if not v]
    if missing:
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")

# ─── API availability flags ───────────────────────────────────────────────────
HAS_VT         = bool(VT_API_KEY)
HAS_ABUSEIPDB  = bool(ABUSEIPDB_API_KEY)
HAS_OTX        = bool(OTX_API_KEY)
HAS_SHODAN     = bool(SHODAN_API_KEY)
HAS_GREYNOISE  = bool(GREYNOISE_API_KEY)
HAS_PHISHTANK  = bool(PHISHTANK_API_KEY)
HAS_ABUSE_CH   = bool(ABUSE_CH_API_KEY)

FEED_DEBUG_MODE: bool = os.getenv("FEED_DEBUG_MODE", "False").lower() in ("true", "1", "yes")


