"""
handlers/phishing_cmd.py - SOC-grade Email Phishing Analysis Engine

Supported input modes:
  /phish <from> | <subject> | <body>     → text-based metadata + content analysis
  /phish (reply to an image)             → image → OCR → full analysis pipeline
  /phish (reply to a message with text)  → raw email body / HTML content analysis

Analysis pipeline:
  1. Domain Analysis         (WHOIS age, SPF/DMARC, typosquatting detection)
  2. Email Authentication    (SPF / DKIM / DMARC from headers or DNS)
  3. Content Analysis        (urgency/reward/CTA/manipulation pattern scoring)
  4. URL Extraction & Check  (regex + VT domain lookups + redirect expansion)
  5. Image OCR               (pytesseract if installed, else graceful fallback)
  6. Final Decision Engine   (risk score → verdict + SOC recommendation)
"""
import re
import io
import asyncio
import logging
import html as html_lib
from urllib.parse import urlparse, urljoin
from typing import Optional

import httpx
from telegram import Update, Message
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

import api_clients as api
import database as db

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
#  Constants & Pattern Libraries
# ══════════════════════════════════════════════════════════════════════════════

_URGENCY_PATTERNS = [
    r'\burgent\b', r'\bimmediately\b', r'\bexpire[sd]?\b', r'\blimited time\b',
    r'\bact now\b', r'\blast chance\b', r'\bdeadline\b', r'\bwithin \d+ hours?\b',
    r'\bsuspended\b', r'\bverif(?:y|ied|ication)\b', r'\baccount.*(?:blocked|locked|disabled)\b',
    r'\bunusual.*activity\b', r'\bsecurity alert\b', r'\byour account\b.*\brisk\b',
]

_REWARD_PATTERNS = [
    r'\bfree\b', r'\bgift\b', r'\bprize\b', r'\bvoucher\b', r'\bcongratulations\b',
    r'\bwinner\b', r'\bwon\b', r'\bclaim.*reward\b', r'\bcashback\b',
    r'\b\$\d+\b', r'\b(?:100|500|1000)\s*(?:USD|EUR|GBP)\b',
]

_CTA_PATTERNS = [
    r'\bclick here\b', r'\bverify.*account\b', r'\bconfirm.*account\b',
    r'\bupdate.*payment\b', r'\bsign in\b', r'\blog.*?in\b', r'\bredeem\b',
    r'\bdownload.*attachment\b', r'\bopen.*link\b', r'\bsubmit.*form\b',
]

_MANIPULATION_PATTERNS = [
    r'\bdon\'?t ignore\b', r'\bfailure to (?:act|respond)\b',
    r'\byour (?:account|card|service).*(?:cancel|terminat)\b',
    r'\bthreat\b.*\blegal\b', r'\bauthorities\b', r'\bpolice\b.*\bnotif\b',
    r'\btax(?:es?)? (?:due|owed|refund)\b', r'\brefund\b.*\bpending\b',
]

# Typosquatting pattern: common brand keywords + look-alike chars
_LEGIT_BRANDS = [
    'google', 'microsoft', 'amazon', 'apple', 'paypal', 'facebook', 'netflix',
    'instagram', 'twitter', 'linkedin', 'dropbox', 'outlook', 'office365',
    'icloud', 'yahoo', 'bank', 'wellsfargo', 'chase', 'citibank', 'hsbc',
    'dhl', 'fedex', 'ups', 'usps', 'ebay', 'walmart', 'steam', 'discord',
]

_SUSPICIOUS_PREFIXES = [
    'login-', 'secure-', 'account-', 'verify-', 'update-', 'support-',
    'helpdesk-', 'billing-', 'payment-', 'signin-', 'auth-', 'portal-',
    'service-', 'mail-', 'webmail-', 'noreply-', 'alert-', 'security-',
]

_URL_PATTERN = re.compile(
    r'https?://[^\s\"\'\<\>\]\)]+', re.IGNORECASE
)

_URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 'goo.gl', 'short.link', 'rb.gy', 'cutt.ly', 'shorturl.at',
}

# Free hosting platforms used in phishing
_SUSPICIOUS_HOSTS = {
    'ngrok.io', 'ngrok-free.app', 'netlify.app', 'vercel.app', 'pages.dev',
    'glitch.me', 'replit.app', 'web.app', 'firebaseapp.com', '000webhostapp.com',
    'weebly.com', 'wixsite.com', 'blogspot.com', 'github.io',
}


# ══════════════════════════════════════════════════════════════════════════════
#  Helper Utilities
# ══════════════════════════════════════════════════════════════════════════════

def _count_pattern_matches(text: str, patterns: list[str]) -> list[str]:
    """Return list of matched pattern labels found in text."""
    text_lower = text.lower()
    hits = []
    for p in patterns:
        if re.search(p, text_lower):
            hits.append(p.replace(r'\b', '').replace('\\', '').strip())
    return hits


def _extract_urls(text: str) -> list[str]:
    """Extract all HTTP/HTTPS URLs from text."""
    found = _URL_PATTERN.findall(text)
    # De-duplicate while preserving order
    seen = set()
    out = []
    for u in found:
        u = u.rstrip('.,;)')
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out[:20]  # Cap at 20 URLs


def _extract_domain_from_email(email_str: str) -> Optional[str]:
    """Extract domain from an email address string like 'Name <user@domain.com>'."""
    m = re.search(r'@([\w\.\-]+)', email_str)
    return m.group(1).lower() if m else None


def _detect_typosquatting(domain: str) -> list[str]:
    """Detect typosquatting / brand impersonation patterns in a domain."""
    findings = []
    domain_lower = domain.lower()
    base = domain_lower.split('.')[0]  # e.g. 'secure-paypa1' from 'secure-paypa1.com'

    # Check for suspicious prefixes
    for prefix in _SUSPICIOUS_PREFIXES:
        if base.startswith(prefix):
            findings.append(f"Suspicious subdomain prefix: '{prefix}'")
            break

    # Check for brand keyword inside domain with extra chars
    for brand in _LEGIT_BRANDS:
        if brand in domain_lower:
            # If the domain ISN'T exactly the brand domain (e.g. paypal.com) → suspicious
            if not (domain_lower == f"{brand}.com" or domain_lower.endswith(f".{brand}.com")):
                findings.append(f"Brand keyword '{brand}' embedded in non-official domain")
                break

    # Homoglyph / numeric substitution check (e.g. paypa1, g00gle, micosoft)
    homoglyphs = {'0': 'o', '1': 'i', '1': 'l', '3': 'e', '4': 'a', '@': 'a'}
    normalized = domain_lower
    for digit, letter in homoglyphs.items():
        normalized = normalized.replace(digit, letter)

    for brand in _LEGIT_BRANDS:
        if brand in normalized and brand not in domain_lower:
            findings.append(f"Possible homoglyph substitution impersonating '{brand}'")
            break

    # Excess hyphens (e.g. secure-account-login-paypal.com)
    if domain_lower.count('-') >= 3:
        findings.append("Excessive hyphens in domain (common phishing pattern)")

    # Long subdomain chain
    labels = domain_lower.split('.')
    if len(labels) >= 5:
        findings.append(f"Unusually deep subdomain ({len(labels)} labels)")

    return findings


def _check_url_risk(url: str) -> dict:
    """Synchronous URL risk analysis (no network calls)."""
    try:
        parsed = urlparse(url)
        host   = parsed.netloc.lower().split(':')[0]
        path   = parsed.path.lower()
    except Exception:
        return {"host": url, "risk": "medium", "flags": ["URL parse error"]}

    flags = []
    risk  = "low"

    # Shortener check
    if host in _URL_SHORTENERS:
        flags.append("URL shortener — destination hidden")
        risk = "high"

    # Suspicious hosting
    for sh in _SUSPICIOUS_HOSTS:
        if host.endswith(sh):
            flags.append(f"Free hosting platform: {sh}")
            risk = "high"
            break

    # Typosquatting in URL domain
    typo_hits = _detect_typosquatting(host)
    if typo_hits:
        flags.extend(typo_hits)
        risk = "critical"

    # IP as host
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
        flags.append("Raw IP address used as host (no domain)")
        risk = "critical"

    # Suspicious path keywords
    suspicious_paths = ['login', 'signin', 'verify', 'secure', 'account', 'update',
                        'password', 'banking', 'credential', 'confirm', 'auth']
    for kw in suspicious_paths:
        if kw in path:
            flags.append(f"Suspicious path keyword: '{kw}'")
            if risk == "low":
                risk = "medium"
            break

    # Very long URL
    if len(url) > 200:
        flags.append("Unusually long URL (obfuscation)")
        if risk == "low":
            risk = "medium"

    return {"host": host, "risk": risk, "flags": flags}


async def _expand_short_url(url: str) -> Optional[str]:
    """Follow redirects to reveal final destination of a shortened URL."""
    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=True, max_redirects=8) as c:
            resp = await c.head(url)
            final = str(resp.url)
            if final != url:
                return final
    except Exception:
        pass
    return None


async def _ocr_image(image_bytes: bytes) -> Optional[str]:
    """
    Extract text from an image using pytesseract (if available).
    Returns None if tesseract is not installed, so the caller can gracefully degrade.
    """
    try:
        import pytesseract
        from PIL import Image
        img = Image.open(io.BytesIO(image_bytes))
        text = await asyncio.to_thread(pytesseract.image_to_string, img)
        return text.strip() if text.strip() else None
    except ImportError:
        logger.info("[Phishing] pytesseract not installed — OCR unavailable")
        return None
    except Exception as e:
        logger.warning(f"[Phishing] OCR error: {e}")
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  Core Analysis Engine
# ══════════════════════════════════════════════════════════════════════════════

async def analyse_phishing(
    sender: str = "",
    subject: str = "",
    body: str = "",
    ocr_text: str = "",
    image_mode: bool = False,
) -> dict:
    """
    Run the full phishing analysis pipeline.
    Returns a structured result dict with all findings.
    """
    result = {
        "sender":         sender,
        "subject":        subject,
        "sender_domain":  None,
        "domain_age":     None,
        "registrar":      None,
        "spf":            "Unknown",
        "dmarc":          "Unknown",
        "typosquatting":  [],
        "urgency_hits":   [],
        "reward_hits":    [],
        "cta_hits":       [],
        "manipulation_hits": [],
        "extracted_urls": [],
        "url_analysis":   [],
        "ocr_available":  False,
        "ocr_text_len":   0,
        "risk_score":     0,
        "verdict":        "SAFE",
        "confidence":     0,
        "attack_type":    "Unknown",
        "indicators":     [],
        "soc_actions":    [],
    }

    full_text = "\n".join(filter(None, [body, ocr_text, subject]))

    # ── 1. Sender domain analysis ──────────────────────────────────────────────
    if sender:
        domain = _extract_domain_from_email(sender)
        if not domain:
            # Maybe just a bare domain was passed
            if re.match(r'^[a-z0-9\.\-]+\.[a-z]{2,}$', sender.lower()):
                domain = sender.lower()
        result["sender_domain"] = domain

        if domain:
            # RDAP / domain age check
            try:
                rdap = await api.rdap_domain(domain)
                if "error" not in rdap:
                    result["registrar"]   = rdap.get("registrar", "Unknown")
                    result["domain_age"]  = rdap.get("creation_date", "Unknown")
            except Exception:
                pass

            # SPF / DMARC DNS check
            try:
                from handlers.email_cmd import check_spf_dmarc
                spf, dmarc = await asyncio.to_thread(check_spf_dmarc, domain)
                result["spf"]   = spf
                result["dmarc"] = dmarc
            except Exception:
                pass

            # Typosquatting
            result["typosquatting"] = _detect_typosquatting(domain)

    # ── 2. Content analysis ────────────────────────────────────────────────────
    if full_text:
        result["urgency_hits"]     = _count_pattern_matches(full_text, _URGENCY_PATTERNS)[:5]
        result["reward_hits"]      = _count_pattern_matches(full_text, _REWARD_PATTERNS)[:5]
        result["cta_hits"]         = _count_pattern_matches(full_text, _CTA_PATTERNS)[:5]
        result["manipulation_hits"]= _count_pattern_matches(full_text, _MANIPULATION_PATTERNS)[:5]

    # ── 3. OCR metadata ───────────────────────────────────────────────────────
    if ocr_text:
        result["ocr_available"] = True
        result["ocr_text_len"]  = len(ocr_text)

    # ── 4. URL extraction & analysis ──────────────────────────────────────────
    raw_urls = _extract_urls(full_text)
    url_analysis_tasks = []
    expanded_cache: dict[str, Optional[str]] = {}

    for url in raw_urls:
        parsed = urlparse(url)
        host = parsed.netloc.lower().split(':')[0]
        if host in _URL_SHORTENERS:
            url_analysis_tasks.append(("expand", url))
        else:
            url_analysis_tasks.append(("check", url))

    # Expand shortened URLs concurrently
    expand_tasks = {url: _expand_short_url(url) for kind, url in url_analysis_tasks if kind == "expand"}
    if expand_tasks:
        expanded_results = await asyncio.gather(*expand_tasks.values(), return_exceptions=True)
        for url, exp in zip(expand_tasks.keys(), expanded_results):
            if isinstance(exp, str):
                expanded_cache[url] = exp

    # Run VT domain check on unique hosts (max 5 to stay within rate limits)
    vt_host_cache: dict[str, dict] = {}
    unique_hosts = []
    for url in raw_urls:
        host = urlparse(url).netloc.lower().split(':')[0]
        if host and host not in unique_hosts:
            unique_hosts.append(host)

    vt_hosts_to_check = [h for h in unique_hosts[:5] if not re.match(r'^\d+\.\d+\.\d+\.\d+$', h)]
    if vt_hosts_to_check and api.config.HAS_VT:
        vt_results = await asyncio.gather(
            *[api.vt_check_domain(h) for h in vt_hosts_to_check],
            return_exceptions=True
        )
        for host, vt_res in zip(vt_hosts_to_check, vt_results):
            if isinstance(vt_res, dict) and "error" not in vt_res:
                vt_host_cache[host] = vt_res

    # Build url_analysis list
    for url in raw_urls[:15]:
        local_risk = _check_url_risk(url)
        host = local_risk["host"]

        # Merge VT data
        vt_data = vt_host_cache.get(host, {})
        vt_malicious = vt_data.get("malicious", 0)
        if vt_malicious > 0:
            local_risk["flags"].append(f"VirusTotal: {vt_malicious} malicious engines")
            local_risk["risk"] = "critical"
        elif "error" not in vt_data and vt_data:
            local_risk["flags"].append("VirusTotal: Clean")

        # Add expansion info
        expanded = expanded_cache.get(url)
        if expanded:
            local_risk["expanded_to"] = expanded
            # Re-check expanded URL
            exp_risk = _check_url_risk(expanded)
            if exp_risk["risk"] in ("high", "critical"):
                local_risk["risk"] = exp_risk["risk"]
                local_risk["flags"].extend(exp_risk["flags"])

        local_risk["url"] = url
        result["url_analysis"].append(local_risk)

    result["extracted_urls"] = raw_urls

    # ── 5. Score computation ───────────────────────────────────────────────────
    score = 0
    indicators = []
    soc_actions = []

    # Domain risk
    if result["typosquatting"]:
        score += 30
        for t in result["typosquatting"][:2]:
            indicators.append(f"⚠️ {t}")
        soc_actions.append("Add sender domain to DNS blocklist")

    # Auth failures
    spf_val   = str(result.get("spf") or "None").lower()
    dmarc_val = str(result.get("dmarc") or "None").lower()
    if spf_val in ("none", "fail", "softfail", "unknown"):
        score += 15
        indicators.append(f"❌ SPF: {'MISSING' if spf_val == 'none' else spf_val.upper()}")
    if dmarc_val in ("none", "unknown"):
        score += 10
        indicators.append("❌ DMARC: NOT CONFIGURED")
    elif "p=none" in dmarc_val:
        score += 5
        indicators.append("⚠️ DMARC policy set to p=none (no enforcement)")

    # New / suspicious domain
    domain_age = result.get("domain_age") or ""
    if domain_age and domain_age not in ("Unknown", ""):
        try:
            from datetime import datetime, timezone
            # Try to parse ISO date
            age_dt = datetime.fromisoformat(str(domain_age).replace("Z", "+00:00"))
            if age_dt.tzinfo is None:
                from datetime import timezone
                age_dt = age_dt.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_old = (now - age_dt).days
            if days_old < 30:
                score += 25
                indicators.append(f"🆕 Domain registered {days_old} days ago (very new)")
                soc_actions.append("Domain age < 30 days — treat as high risk infrastructure")
            elif days_old < 180:
                score += 10
                indicators.append(f"🆕 Domain registered {days_old} days ago (recent)")
        except Exception:
            pass

    # Content signals
    if result["urgency_hits"]:
        score += len(result["urgency_hits"]) * 5
        indicators.append(f"⏰ Urgency language detected ({len(result['urgency_hits'])} patterns)")
    if result["reward_hits"]:
        score += len(result["reward_hits"]) * 5
        indicators.append(f"🎁 Reward/bait language detected ({len(result['reward_hits'])} patterns)")
    if result["cta_hits"]:
        score += len(result["cta_hits"]) * 4
        indicators.append(f"🖱️ Suspicious CTA patterns ({len(result['cta_hits'])} found)")
    if result["manipulation_hits"]:
        score += len(result["manipulation_hits"]) * 6
        indicators.append(f"🧠 Emotional manipulation detected ({len(result['manipulation_hits'])} patterns)")

    # URL signals
    critical_urls = [u for u in result["url_analysis"] if u.get("risk") == "critical"]
    high_urls     = [u for u in result["url_analysis"] if u.get("risk") == "high"]
    if critical_urls:
        score += 25
        indicators.append(f"🔗 {len(critical_urls)} critical-risk URL(s) detected")
        soc_actions.append("Block URLs at proxy/firewall level")
        soc_actions.append("Search email logs for users who received this message")
    elif high_urls:
        score += 12
        indicators.append(f"🔗 {len(high_urls)} high-risk URL(s) detected")
        soc_actions.append("Review and potentially block flagged URLs")

    if any("URL shortener" in f for u in result["url_analysis"] for f in u.get("flags", [])):
        score += 8
        indicators.append("🔀 URL shortener used to hide destination")

    # OCR image contribution
    if image_mode and result["ocr_available"] and result["ocr_text_len"] > 50:
        indicators.append(f"📸 OCR extracted {result['ocr_text_len']} chars from email screenshot")

    score = min(score, 100)
    result["risk_score"] = score
    result["indicators"] = indicators

    # ── 6. Verdict + attack type ───────────────────────────────────────────────
    if score >= 70:
        result["verdict"]     = "PHISHING"
        result["confidence"]  = min(85 + (score - 70) // 3, 99)
    elif score >= 45:
        result["verdict"]     = "SUSPICIOUS"
        result["confidence"]  = 60 + (score - 45)
    elif score >= 20:
        result["verdict"]     = "LOW RISK"
        result["confidence"]  = 50
    else:
        result["verdict"]     = "SAFE"
        result["confidence"]  = 80

    # Attack type classification
    has_reward  = bool(result["reward_hits"])
    has_urgency = bool(result["urgency_hits"])
    has_cta     = bool(result["cta_hits"])
    has_crit_url= bool(critical_urls)

    if has_crit_url and has_cta:
        result["attack_type"] = "Credential Phishing"
        soc_actions.insert(0, "Initiate credential reset for targeted users")
    elif has_reward:
        result["attack_type"] = "Reward / Prize Scam"
    elif result["typosquatting"] and has_urgency:
        result["attack_type"] = "Spoofed Corporate Email"
        soc_actions.append("Check SPF/DMARC alignment on sender domain")
    elif has_crit_url:
        result["attack_type"] = "Malware Delivery"
        soc_actions.append("Run IOC hunt for URLs in endpoint logs")
    elif has_urgency:
        result["attack_type"] = "Account Compromise Attempt"
    else:
        result["attack_type"] = "Unknown / Suspicious"

    # Final SOC actions
    if score >= 70:
        soc_actions.append("Quarantine email and notify recipients")
        soc_actions.append("File incident report and escalate to Tier 2")
    elif score >= 45:
        soc_actions.append("Flag for analyst manual review")

    result["soc_actions"] = list(dict.fromkeys(soc_actions))  # dedup preserve order
    return result


# ══════════════════════════════════════════════════════════════════════════════
#  Report Formatter
# ══════════════════════════════════════════════════════════════════════════════

def _verdict_emoji(verdict: str) -> str:
    return {
        "PHISHING":  "🔴",
        "SUSPICIOUS": "🟠",
        "LOW RISK":  "🟡",
        "SAFE":      "🟢",
    }.get(verdict, "⚪")


def _risk_bar(score: int) -> str:
    """Render a simple text risk bar (10 blocks)."""
    filled = score // 10
    return "█" * filled + "░" * (10 - filled)


def format_phishing_report(r: dict, image_mode: bool = False) -> str:
    sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
    verdict_em = _verdict_emoji(r["verdict"])
    risk_bar   = _risk_bar(r["risk_score"])

    # Header
    source_label = "📸 EMAIL SCREENSHOT" if image_mode else "📧 EMAIL CONTENT"
    msg = (
        f"🛡 <b>PHISHING THREAT REPORT</b>\n"
        f"<code>{sep}</code>\n"
        f"📥 Source: {source_label}\n\n"
    )

    # Sender block
    if r.get("sender"):
        msg += f"<b>📨 Sender:</b> <code>{html_lib.escape(r['sender'])}</code>\n"
    if r.get("sender_domain"):
        msg += f"<b>🌐 Sender Domain:</b> <code>{html_lib.escape(r['sender_domain'])}</code>\n"
    if r.get("subject"):
        subj_disp = r["subject"][:60] + ("…" if len(r["subject"]) > 60 else "")
        msg += f"<b>📋 Subject:</b> <code>{html_lib.escape(subj_disp)}</code>\n"
    msg += "\n"

    # Domain info
    if r.get("registrar") or r.get("domain_age"):
        msg += "<b>📅 Domain Intelligence:</b>\n"
        if r.get("domain_age"):
            msg += f"  • Created: <code>{html_lib.escape(str(r['domain_age'])[:20])}</code>\n"
        if r.get("registrar"):
            msg += f"  • Registrar: <code>{html_lib.escape(str(r['registrar'])[:40])}</code>\n"
        msg += "\n"

    # Auth check
    spf_raw   = str(r.get("spf") or "None")
    dmarc_raw = str(r.get("dmarc") or "None")
    spf_em    = "🟢" if "pass" in spf_raw.lower() and "v=spf1" in spf_raw.lower() else \
                "🔴" if spf_raw.lower() in ("none", "fail", "unknown") else "🟡"
    dmarc_em  = "🟢" if "v=dmarc1" in dmarc_raw.lower() and "p=reject" in dmarc_raw.lower() else \
                "🔴" if dmarc_raw.lower() in ("none", "unknown") else "🟡"

    spf_display   = "NOT FOUND" if spf_raw.lower() in ("none", "unknown") else spf_raw[:60]
    dmarc_display = "NOT FOUND" if dmarc_raw.lower() in ("none", "unknown") else dmarc_raw[:60]

    msg += (
        f"<b>🔒 Email Authentication:</b>\n"
        f"  {spf_em} SPF:   <code>{html_lib.escape(spf_display)}</code>\n"
        f"  {dmarc_em} DMARC: <code>{html_lib.escape(dmarc_display)}</code>\n\n"
    )

    # Typosquatting
    if r.get("typosquatting"):
        msg += "<b>🎭 Domain Spoofing Detected:</b>\n"
        for t in r["typosquatting"][:3]:
            msg += f"  ⚠️ {html_lib.escape(t)}\n"
        msg += "\n"

    # URL analysis
    if r.get("url_analysis"):
        msg += f"<b>🔗 Extracted URLs ({len(r['url_analysis'])}):</b>\n"
        for ua in r["url_analysis"][:8]:
            risk_em = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(ua["risk"], "⚪")
            url_disp = ua["url"]
            if len(url_disp) > 55:
                url_disp = url_disp[:52] + "…"
            flags_str = "; ".join(ua.get("flags", [])[:2])
            msg += f"  {risk_em} <code>{html_lib.escape(url_disp)}</code>\n"
            if flags_str:
                msg += f"       <i>{html_lib.escape(flags_str)}</i>\n"
            if ua.get("expanded_to"):
                exp_disp = ua["expanded_to"][:52] + ("…" if len(ua["expanded_to"]) > 52 else "")
                msg += f"       ↳ Expanded: <code>{html_lib.escape(exp_disp)}</code>\n"
        msg += "\n"

    # Content signals
    if any([r.get("urgency_hits"), r.get("reward_hits"), r.get("cta_hits"), r.get("manipulation_hits")]):
        msg += "<b>🧠 Content Signals:</b>\n"
        if r.get("urgency_hits"):
            msg += f"  ⏰ Urgency patterns: <b>{len(r['urgency_hits'])}</b>\n"
        if r.get("reward_hits"):
            msg += f"  🎁 Reward/bait: <b>{len(r['reward_hits'])}</b>\n"
        if r.get("cta_hits"):
            msg += f"  🖱️ Suspicious CTAs: <b>{len(r['cta_hits'])}</b>\n"
        if r.get("manipulation_hits"):
            msg += f"  🧠 Manipulation: <b>{len(r['manipulation_hits'])}</b>\n"
        msg += "\n"

    # OCR info
    if image_mode and r.get("ocr_available"):
        msg += f"<b>📸 OCR:</b> Extracted <code>{r['ocr_text_len']}</code> characters from image\n\n"
    elif image_mode and not r.get("ocr_available"):
        msg += "<b>📸 OCR:</b> <i>pytesseract not installed — text extracted from image metadata only</i>\n\n"

    # Indicators
    if r.get("indicators"):
        msg += "<b>🚨 Detection Indicators:</b>\n"
        for ind in r["indicators"][:8]:
            msg += f"  {html_lib.escape(ind)}\n"
        msg += "\n"

    # Final verdict block
    msg += (
        f"<code>{sep}</code>\n"
        f"<b>📊 Risk Score:</b>  <code>{r['risk_score']}/100</code>  [{risk_bar}]\n"
        f"<b>🎯 Verdict:</b>     {verdict_em} <b>{r['verdict']}</b>\n"
        f"<b>🔬 Attack Type:</b> <code>{r['attack_type']}</code>\n"
        f"<b>📈 Confidence:</b>  <code>{r['confidence']}%</code>\n\n"
    )

    # Action block removed — Phase 12.2 (evidence-only platform)

    msg += f"\n<code>{sep}</code>\n<i>Phishing Analysis Engine — Investigator Mode</i>"
    return msg


# ══════════════════════════════════════════════════════════════════════════════
#  Telegram Command Handler
# ══════════════════════════════════════════════════════════════════════════════

async def phish_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    /phish — SOC-grade email phishing analysis.

    Usage modes:
      /phish <from_email> | <subject> | <body text>
      Reply /phish to a message containing email content
      Send /phish and reply to an email screenshot image
    """
    message = update.effective_message
    image_mode = False
    sender  = ""
    subject = ""
    body    = ""
    ocr_text = ""

    # ── Mode 1: Reply to an image (screenshot analysis) ─────────────────────
    replied = message.reply_to_message
    if replied and (replied.photo or replied.document):
        image_mode = True
        thinking = await message.reply_text(
            "📸 <b>Downloading email screenshot for OCR analysis...</b>",
            parse_mode=ParseMode.HTML
        )
        try:
            # Get file
            if replied.photo:
                file_obj = await replied.photo[-1].get_file()
            else:
                file_obj = await replied.document.get_file()

            img_bytes = await file_obj.download_as_bytearray()
            await thinking.edit_text(
                "🔍 <b>Running OCR + phishing analysis pipeline...</b>",
                parse_mode=ParseMode.HTML
            )
            ocr_text = await _ocr_image(bytes(img_bytes)) or ""
            if not ocr_text and not sender:
                # Still proceed — we can do URL-less content scoring
                ocr_text = ""

        except Exception as e:
            logger.error(f"[Phish] Image download/OCR error: {e}")
            await thinking.edit_text(
                f"❌ <b>Image processing failed:</b> <code>{html_lib.escape(str(e))}</code>",
                parse_mode=ParseMode.HTML
            )
            return

    # ── Mode 2: Reply to a text message ─────────────────────────────────────
    elif replied and replied.text and not context.args:
        body = replied.text.strip()
        thinking = await message.reply_text(
            "🔍 <b>Analysing email content for phishing indicators...</b>",
            parse_mode=ParseMode.HTML
        )

    # ── Mode 3: Inline args — pipe-separated fields ─────────────────────────
    elif context.args:
        raw = " ".join(context.args).strip()
        parts = [p.strip() for p in raw.split("|")]
        if len(parts) >= 1:
            sender = parts[0]
        if len(parts) >= 2:
            subject = parts[1]
        if len(parts) >= 3:
            body = " | ".join(parts[2:])

        thinking = await message.reply_text(
            "🔍 <b>Running phishing analysis pipeline...</b>",
            parse_mode=ParseMode.HTML
        )

    # ── No useful input ───────────────────────────────────────────────────────
    else:
        await message.reply_text(
            "📧 <b>Email Phishing Analyser</b>\n\n"
            "<b>Usage:</b>\n"
            "  <code>/phish sender@domain.com | Subject Line | Body text here</code>\n\n"
            "  Or <b>reply</b> <code>/phish</code> to:\n"
            "  • A <b>text message</b> containing email body/content\n"
            "  • An <b>image/screenshot</b> of the email\n\n"
            "<i>Analyses sender domain, authentication, URL patterns, and content for phishing indicators.</i>",
            parse_mode=ParseMode.HTML
        )
        return

    # ── Run analysis ─────────────────────────────────────────────────────────
    try:
        result = await analyse_phishing(
            sender=sender,
            subject=subject,
            body=body,
            ocr_text=ocr_text,
            image_mode=image_mode,
        )
        report = format_phishing_report(result, image_mode=image_mode)

        await thinking.delete()
        # Send in chunks if too long
        if len(report) > 4000:
            chunks = [report[i:i+4000] for i in range(0, len(report), 4000)]
            for chunk in chunks:
                await message.reply_text(chunk, parse_mode=ParseMode.HTML,
                                         disable_web_page_preview=True)
        else:
            await message.reply_text(report, parse_mode=ParseMode.HTML,
                                     disable_web_page_preview=True)

    except Exception as e:
        logger.error(f"[Phish] Analysis pipeline error: {e}", exc_info=True)
        try:
            await thinking.delete()
        except Exception:
            pass
        await message.reply_text(
            f"❌ <b>Analysis failed:</b> <code>{html_lib.escape(str(e))}</code>",
            parse_mode=ParseMode.HTML
        )
