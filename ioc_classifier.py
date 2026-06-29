"""
ioc_classifier.py - Automatic IOC type detection
Classifies an input string as: ip, domain, url, md5, sha1, sha256, or unknown.
"""
import re

# ─── Regex patterns ───────────────────────────────────────────────────────────
_RE_IPV4   = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_RE_IPV6   = re.compile(r"^[0-9a-fA-F:]{2,39}$")
_RE_MD5    = re.compile(r"^[a-fA-F0-9]{32}$")
_RE_SHA1   = re.compile(r"^[a-fA-F0-9]{40}$")
_RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_RE_URL    = re.compile(r"^https?://", re.IGNORECASE)
_RE_DOMAIN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

IOC_TYPES = {
    "ip":     "🌐 IP Address",
    "domain": "🔗 Domain",
    "url":    "🔗 URL",
    "md5":    "🔒 MD5 Hash",
    "sha1":   "🔒 SHA1 Hash",
    "sha256": "🔒 SHA256 Hash",
    "unknown":"❓ Unknown",
}

def classify(value: str) -> str:
    """Return the IOC type string for the given value."""
    v = value.strip()

    if _RE_URL.match(v):
        return "url"

    if _RE_SHA256.match(v):
        return "sha256"

    if _RE_SHA1.match(v):
        return "sha1"

    if _RE_MD5.match(v):
        return "md5"

    if _RE_IPV4.match(v):
        # validate each octet
        octets = v.split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            return "ip"

    if _RE_IPV6.match(v) and ":" in v:
        return "ip"

    if _RE_DOMAIN.match(v):
        return "domain"

    return "unknown"


def friendly_type(ioc_type: str) -> str:
    return IOC_TYPES.get(ioc_type, "❓ Unknown")
