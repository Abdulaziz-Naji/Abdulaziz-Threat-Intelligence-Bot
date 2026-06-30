"""
ti_report_builder.py - Phase 12: Professional Threat Intelligence Report Engine.

Evidence-only, analyst-grade TI reports.
No recommendations. No explanations. No decisions.
Only intelligence.

Supports: IP | Domain | URL | MD5 | SHA1 | SHA256 | Email
"""
import html as _html
import socket
from datetime import datetime, timezone
from typing import Optional

_SEP = "━━━━━━━━━━━━━━━━━━━━━━━━━━"


# ─── Helpers ───────────────────────────────────────────────────────────────────

def _e(value) -> str:
    """HTML-escape any string coming from external APIs."""
    if value is None:
        return ""
    return _html.escape(str(value))


_IOC_TYPE_LABELS = {
    "ip":     "IPv4 Address",
    "domain": "Domain",
    "url":    "URL",
    "md5":    "MD5 Hash",
    "sha1":   "SHA1 Hash",
    "sha256": "SHA256 Hash",
    "email":  "Email Address",
}

_FLAG_MAP = {
    "US": "🇺🇸", "RU": "🇷🇺", "CN": "🇨🇳", "DE": "🇩🇪", "NL": "🇳🇱",
    "FR": "🇫🇷", "GB": "🇬🇧", "BR": "🇧🇷", "IR": "🇮🇷", "UA": "🇺🇦",
    "RO": "🇷🇴", "PL": "🇵🇱", "IN": "🇮🇳", "JP": "🇯🇵", "KR": "🇰🇷",
    "CA": "🇨🇦", "AU": "🇦🇺", "SG": "🇸🇬", "HK": "🇭🇰", "SE": "🇸🇪",
    "NO": "🇳🇴", "FI": "🇫🇮", "CH": "🇨🇭", "IT": "🇮🇹", "ES": "🇪🇸",
    "TR": "🇹🇷", "CZ": "🇨🇿", "BG": "🇧🇬", "MD": "🇲🇩", "LV": "🇱🇻",
    "LT": "🇱🇹", "EE": "🇪🇪", "BY": "🇧🇾", "KZ": "🇰🇿", "SA": "🇸🇦",
    "AE": "🇦🇪", "IL": "🇮🇱", "EG": "🇪🇬", "ZA": "🇿🇦", "NG": "🇳🇬",
    "MX": "🇲🇽", "AR": "🇦🇷", "CL": "🇨🇱", "CO": "🇨🇴", "VE": "🇻🇪",
    "ID": "🇮🇩", "MY": "🇲🇾", "TH": "🇹🇭", "VN": "🇻🇳", "PK": "🇵🇰",
    "BD": "🇧🇩", "NG": "🇳🇬", "ET": "🇪🇹",
}


def _flag(cc: str) -> str:
    return _FLAG_MAP.get(str(cc).upper(), "🌐")


# ─── Threat Level ──────────────────────────────────────────────────────────────

def _threat_level(score: int) -> tuple[str, str]:
    """Returns (level_label, emoji)."""
    if score >= 75:
        return "Malicious", "🔴"
    if score >= 45:
        return "High Risk", "🟠"
    if score >= 15:
        return "Suspicious", "🟡"
    return "Clean", "🟢"


# ─── Infrastructure Context ────────────────────────────────────────────────────

def _detect_infra_type(isp: str, org: str, usage_type: str, is_tor: bool) -> list[str]:
    """Detect infrastructure type from ISP/org/usage strings."""
    types = []
    isp_l = str(isp).lower()
    org_l = str(org).lower()
    usage_l = str(usage_type).lower()

    if is_tor or "tor" in isp_l or "tor" in org_l:
        types.append("Tor Exit Node")
    if any(k in isp_l or k in org_l for k in ("vpn", "nordvpn", "expressvpn", "mullvad", "protonvpn", "hidemyass")) or "vpn" in usage_l:
        types.append("VPN Service")
    if "cloudflare" in isp_l or "fastly" in isp_l or "akamai" in isp_l or "cloudfront" in isp_l or "cdn" in usage_l:
        types.append("CDN")
    if "aws" in isp_l or "amazon" in isp_l:
        types.append("AWS")
    elif "azure" in isp_l or ("microsoft" in isp_l and "azure" in org_l):
        types.append("Azure")
    elif "google" in isp_l and ("cloud" in isp_l or "cloud" in org_l):
        types.append("GCP")
    elif any(k in isp_l or k in org_l for k in ("digitalocean", "linode", "hetzner", "ovh", "leaseweb", "choopa", "vultr", "m247", "flokinet")):
        types.append("Hosting Provider")
    elif "hosting" in isp_l or "hosting" in org_l or "datacenter" in usage_l:
        types.append("Hosting Provider")
    if any(k in isp_l or k in org_l for k in ("telecom", "comcast", "charter", "at&t", "verizon", "orange", "bt group", "rogers")) or "residential" in usage_l:
        types.append("Residential ISP")
    if "gov" in isp_l or "gov" in org_l or "government" in usage_l:
        types.append("Government Network")
    if "edu" in isp_l or "university" in isp_l or "university" in usage_l:
        types.append("Educational Network")

    return types


# ─── Intelligence Classification ───────────────────────────────────────────────

_CLASSIFICATION_RULES: list[tuple[list[str], str]] = [
    (["ransomware", "locker", "crypt", "filecoder", "wncry", "lockbit", "blackcat", "conti", "ryuk", "revil", "darkside"],
     "Ransomware Infrastructure"),
    (["c2", "command and control", "command & control", "cobalt strike", "cobaltstrike", "metasploit",
      "havoc", "brute ratel", "sliver", "nighthawk"],
     "C2 Infrastructure"),
    (["phishing", "credential phishing", "account takeover"],
     "Phishing Infrastructure"),
    (["credential stealer", "stealer", "infostealer", "lumma", "redline", "vidar", "raccoon", "azorult", "meta stealer"],
     "Credential Stealer"),
    (["botnet", "mirai", "bashlite", "qakbot", "dridex", "emotet", "trickbot"],
     "Botnet Infrastructure"),
    (["malware distribution", "dropper", "loader", "downloader", "stager", "malware"],
     "Malware Distribution"),
    (["spam", "spammer", "bulk mail"],
     "Spam Infrastructure"),
    (["apt", "nation-state", "nation state", "advanced persistent"],
     "APT Infrastructure"),
    (["exploit", "vulnerability", "cve-"],
     "Exploit Infrastructure"),
    (["backdoor", "rat", "remote access trojan", "remote access tool"],
     "Backdoor / RAT"),
    (["cryptominer", "mining", "coin miner", "monero"],
     "Cryptomining"),
    (["scanning", "scanner", "port scan", "reconnaissance"],
     "Scanning Activity"),
]


# ─── Direct-Evidence Classification Sources ──────────────────────────────────
#
# Classification ONLY derives from these authoritative sources:
#   1. ThreatFox     — threat_category field (direct IOC classification)
#   2. MalwareBazaar — threat_category field (direct file classification)
#   3. URLHaus       — threat_category / tags (direct URL classification)
#   4. VirusTotal    — threat_label (vendor consensus label)
#   5. VirusTotal    — categories (vendor-assigned, domain/URL only)
#   6. GreyNoise     — classification + name (direct IP classification)
#   7. AbuseIPDB     — is_tor (direct IP attribute)
#
# NOT included (these are Evidence Context, not classification):
#   OTX pulse names, OTX pulse tags, OTX malware_family
#   Community comments, blog articles, threat reports, GitHub refs

_AUTHORITATIVE_FEED_SOURCES = {"threatfox", "malwarebazaar", "urlhaus"}


def _detect_classification(
    vt: dict,
    feeds: list,
    abuse: dict,
    greynoise: dict,
) -> list[str]:
    """
    Detect threat classification from DIRECT evidence only.

    OTX pulses, community comments, and text mentions are NOT used here.
    Those belong in Evidence Context.
    """
    found_labels: set[str] = set()
    signals: list[str] = []

    # ── VirusTotal threat_label (vendor consensus, highest precision) ──────
    if vt and not vt.get("error"):
        label = str(vt.get("threat_label") or "").strip()
        if label:
            signals.append(label.lower())
        # VT categories — filter to security/threat-relevant only (skip generic ones)
        _THREAT_KEYWORDS = (
            "phish", "malware", "suspicious", "botnet", "c2", "command",
            "ransom", "compromise", "exploit", "spam", "scam", "fraud",
            "trojan", "backdoor", "adware", "spyware", "cryptomining",
            "porn", "adult", "gambling", "hacking", "weapons",
        )
        cats = vt.get("categories") or {}
        if isinstance(cats, dict):
            for v in cats.values():
                val = str(v).lower()
                if any(kw in val for kw in _THREAT_KEYWORDS):
                    signals.append(val)

    # ── Authoritative feeds: ThreatFox, MalwareBazaar, URLHaus ───────────
    for f in (feeds or []):
        src = str(f.get("source") or "").lower().strip()
        if src not in _AUTHORITATIVE_FEED_SOURCES:
            continue  # OTX and generic feeds → Evidence Context, not here
        cat = str(f.get("threat_category") or "").lower()
        if cat:
            signals.append(cat)
        # URLHaus/MalwareBazaar tags
        try:
            import json
            rd = json.loads(f.get("raw_data") or "{}")
            tags = rd.get("tags") or []
            if isinstance(tags, list):
                signals += [str(t).lower() for t in tags]
            mfam = rd.get("malware_family") or ""
            if mfam:
                signals.append(str(mfam).lower())
        except Exception:
            pass

    # ── GreyNoise — direct IP classification ─────────────────────────────
    if greynoise and not greynoise.get("error"):
        gn_class = str(greynoise.get("classification") or "").lower()
        gn_name  = str(greynoise.get("name") or "").lower()
        # Only use name if GreyNoise specifically flagged it (not just noise)
        if gn_class in ("malicious",):
            signals.append(gn_class)
            if gn_name and gn_name not in ("unknown", ""):
                signals.append(gn_name)
        elif gn_class in ("benign",):
            pass  # Benign → no classification label
        else:
            # scanning / noise → Internet Scanner only if GreyNoise confirmed
            riot = greynoise.get("riot", False)
            noise = greynoise.get("noise", False)
            if not riot and noise:
                signals.append("scanning")

    # ── AbuseIPDB: only Tor (direct IP attribute) ─────────────────────────
    if abuse and not abuse.get("error"):
        if abuse.get("is_tor"):
            signals.append("tor")

    all_signals = " ".join(signals)

    for keywords, label in _CLASSIFICATION_RULES:
        if any(kw in all_signals for kw in keywords):
            found_labels.add(label)

    # "Tor Exit Node" is infrastructure, not a threat classification
    # — handled by _detect_infra_type(), not here
    found_labels.discard("Tor Exit Node")

    return sorted(found_labels)


# ─── Evidence Context (OTX Pulses + Non-Authoritative References) ─────────────

def _build_evidence_context(otx: dict, ioc: str) -> str:
    """
    Build EVIDENCE CONTEXT section from OTX pulses.

    These are references to the IOC appearing inside reports/articles/pulses.
    They are NOT direct evidence about what the IOC does.
    They must NEVER affect Threat Classification.
    """
    return ""

    # Sort newest first by created date
    def _pulse_date(p: dict) -> str:
        return str(p.get("created") or p.get("modified") or "")[:10]

    sorted_pulses = sorted(pulses, key=_pulse_date, reverse=True)
    total_count   = len(pulses)
    show_count    = min(5, total_count)
    counter_note  = (
        f"Showing latest {show_count} of {total_count} pulses\n"
        if total_count > 5 else ""
    )

    lines: list[str] = [
        f"<code>{_SEP}</code>\n"
        f"\U0001f4ce <b>EVIDENCE CONTEXT</b>\n"
        f"<code>{_SEP}</code>\n"
        f"<b>Mentioned In</b>    {total_count} OTX pulse(s)\n"
        f"<b>Relationship</b>    IOC referenced inside community reports\n"
    ]
    if counter_note:
        lines.append(f"<i>{counter_note}</i>")
    lines.append("\n")

    for pulse in sorted_pulses[:5]:
        name     = str(pulse.get("name") or "").strip()[:70]
        pub_date = _pulse_date(pulse)
        pulse_id = str(pulse.get("id") or "").strip()

        # Safe author extraction — never expose raw dicts
        _raw_author = pulse.get("author_name") or pulse.get("author") or ""
        if isinstance(_raw_author, dict):
            author = str(
                _raw_author.get("username")
                or _raw_author.get("name")
                or _raw_author.get("id")
                or "anonymous"
            ).strip()[:30]
        else:
            author = str(_raw_author).strip()[:30]
        # Strip any residual dict-like strings (safety net)
        if author.startswith("{") or author.startswith("<"):
            author = "anonymous"

        otx_url  = f"https://otx.alienvault.com/pulse/{pulse_id}" if pulse_id else ""
        tags     = [str(t) for t in (pulse.get("tags") or [])[:4] if t]
        tags_str = ", ".join(tags) if tags else ""

        lines.append(f"<b>Pulse</b>       <i>{_e(name)}</i>\n")
        if pub_date:
            lines.append(f"<b>Published</b>  <code>{_e(pub_date)}</code>\n")
        lines.append(f"<b>Source</b>     AlienVault OTX\n")
        if author and author not in ("anonymous", ""):
            lines.append(f"<b>Author</b>     <code>{_e(author)}</code>\n")
        if pulse_id:
            lines.append(f"<b>Pulse ID</b>   <code>{_e(pulse_id)}</code>\n")
        if tags_str:
            lines.append(f"<b>Tags</b>       <code>{_e(tags_str)}</code>\n")
        if otx_url:
            lines.append(f"<b>Reference</b>  <code>{_e(otx_url)}</code>\n")
        lines.append("\n")

    return "".join(lines)


# Trusted/high-signal vendors shown first
_PRIORITY_VENDORS = [
    "Microsoft", "Kaspersky", "CrowdStrike", "SentinelOne", "Elastic",
    "Sophos", "ESET", "BitDefender", "Fortinet", "Palo Alto Networks",
    "Symantec", "Malwarebytes", "TrendMicro", "F-Secure", "Avast",
    "DrWeb", "G-Data", "Avira", "McAfee", "AVG",
]


# Label map for display normalization
_VT_LABEL_MAP: dict[str, str] = {
    "malicious":  "Malicious",
    "suspicious": "Suspicious",
    "phishing":   "Phishing",
    "malware":    "Malware",
}
# Categories we display (anything else is noise)
_VT_DISPLAY_CATS = frozenset(_VT_LABEL_MAP.keys())


def _build_vt_vendor_table(vt: dict) -> str:
    """Build full per-vendor detection block with category summary.

    Returns HTML string ready to embed, or '' when there are no detections.
    Includes every vendor whose category is malicious/suspicious/phishing/malware.
    """
    if not vt or vt.get("error"):
        return ""

    results = vt.get("last_analysis_results") or {}
    if not isinstance(results, dict) or not results:
        return ""

    # ── Collect every flagging vendor ─────────────────────────────────────
    detections: list[tuple[str, str, str]] = []   # (vendor, display_label, result_str)

    for vendor, detail in results.items():
        if not isinstance(detail, dict):
            continue
        cat = str(detail.get("category") or "").lower().strip()
        if cat not in _VT_DISPLAY_CATS:
            continue
        result_raw = str(detail.get("result") or "").strip()
        # If vendor gave a specific threat name, show it; otherwise fall back to category label
        if result_raw and result_raw.lower() not in {
            "malicious", "suspicious", "phishing", "malware", "generic", "undetected", ""
        }:
            display_result = result_raw[:55]
        else:
            display_result = _VT_LABEL_MAP.get(cat, cat.capitalize())
        detections.append((vendor, _VT_LABEL_MAP.get(cat, cat.capitalize()), display_result))

    if not detections:
        return ""

    # ── Sort: priority vendors first, then by label, then alphabetically ──
    def _sort_key(item: tuple) -> tuple:
        vendor, label, _ = item
        _order = {"Malicious": 0, "Malware": 1, "Phishing": 2, "Suspicious": 3}
        return (0 if vendor in _PRIORITY_VENDORS else 1, _order.get(label, 9), vendor)

    detections.sort(key=_sort_key)

    # ── Summary counts ────────────────────────────────────────────────────
    from collections import Counter as _Counter
    counts = _Counter(lbl for _, lbl, _ in detections)

    summary_lines = []
    for lbl in ("Malicious", "Malware", "Phishing", "Suspicious"):
        n = counts.get(lbl, 0)
        if n > 0:
            summary_lines.append(f"  <b>{_e(lbl)}</b>    <code>{n}</code>")

    # ── Vendor bullet list ────────────────────────────────────────────────
    vendor_lines = []
    for vendor, label, result in detections:
        vendor_lines.append(f"  \u2022 <b>{_e(vendor)}</b>    <code>{_e(result)}</code>")

    parts_out: list[str] = []
    # Only show Summary when there are 2+ distinct label types
    if len(counts) >= 2 and summary_lines:
        parts_out.append(f"<b>Summary</b>\n" + "\n".join(summary_lines))
    if vendor_lines:
        parts_out.append(f"<b>Detections</b>\n" + "\n".join(vendor_lines))

    return "\n".join(parts_out)


def _build_score_contributors(components: dict) -> str:
    return ""


def _build_community_intel(comments: list) -> str:
    """Build VT community comments block. Returns empty string if no comments."""
    return ""

    lines = [
        f"\n<code>{_SEP}</code>",
        f"💬 <b>COMMUNITY INTELLIGENCE</b>",
        f"<code>{_SEP}</code>",
        f"<b>Comments:</b> {len(comments)}\n",
    ]

    for c in comments[:5]:
        date_raw = str(c.get("date", ""))[:10]
        author = _e(str(c.get("author", "unknown"))[:30])
        text = _e(str(c.get("text", ""))[:200].strip())
        lines.append(f"<b>{date_raw}</b>  <i>{author}</i>")
        lines.append(f"<code>{text}</code>\n")

    return "\n".join(lines)


# ─── RDAP IP Parser ───────────────────────────────────────────────────────────

def _parse_rdap_ip_info(rdap_data: dict) -> dict:
    """Parse raw RDAP JSON for an IP address into a flat info dict."""
    if not rdap_data or "error" in rdap_data or not isinstance(rdap_data, dict):
        return {}

    info = {
        "netname":      rdap_data.get("name", ""),
        "inetnum":      f"{rdap_data.get('startAddress', '')} - {rdap_data.get('endAddress', '')}".strip(" -"),
        "country":      rdap_data.get("country", ""),
        "parent_network": rdap_data.get("parentHandle", ""),
        "organization": "",
        "abuse_contact": "",
        "created_date": "",
        "updated_date": "",
    }

    for ev in rdap_data.get("events", []):
        if not isinstance(ev, dict):
            continue
        action = ev.get("eventAction", "")
        date = ev.get("eventDate", "")[:10] if ev.get("eventDate") else ""
        if action == "registration":
            info["created_date"] = date
        elif action == "last changed":
            info["updated_date"] = date

    def _vcard(entity: dict) -> dict:
        contact = {"name": "", "email": ""}
        arr = entity.get("vcardArray", [])
        if len(arr) > 1 and isinstance(arr[1], list):
            for field in arr[1]:
                if not isinstance(field, list) or len(field) < 4:
                    continue
                if field[0] == "fn":
                    contact["name"] = str(field[3])
                elif field[0] == "email":
                    contact["email"] = str(field[3])
        return contact

    def _traverse(entities: list) -> None:
        if not isinstance(entities, list):
            return
        for ent in entities:
            if not isinstance(ent, dict):
                continue
            roles = ent.get("roles", [])
            c = _vcard(ent)
            if "abuse" in roles and c["email"] and not info["abuse_contact"]:
                info["abuse_contact"] = c["email"]
            if not info["organization"] and c["name"]:
                info["organization"] = c["name"]
            if ent.get("entities"):
                _traverse(ent["entities"])

    _traverse(rdap_data.get("entities", []))
    return info


# ─── Main Report Builder ───────────────────────────────────────────────────────

def build_ti_report(
    ioc: str,
    ioc_type: str,
    *,
    vt: dict = None,
    abuse: dict = None,
    otx: dict = None,
    geo: dict = None,
    shodan: dict = None,
    greynoise: dict = None,
    rdap: dict = None,
    dns_records: dict = None,
    feeds: list = None,
    in_watchlist: bool = False,
    case_correlations: list = None,
    comments: list = None,
    from_cache: bool = False,
    passive_dns: dict = None,
    related_urls: dict = None,
    related_hashes: dict = None,
) -> tuple[str, dict]:
    """
    Build a professional, evidence-only Threat Intelligence report.

    Returns:
        (html_message: str, result_dict: dict)

    No recommendations. No actions. No explanations.
    Only intelligence.
    """
    import ioc_risk_scoring as scoring

    # Defaults
    vt               = vt               or {}
    abuse            = abuse            or {}
    otx              = otx              or {}
    geo              = geo              or {}
    shodan           = shodan           or {}
    greynoise        = greynoise        or {}
    rdap             = rdap             or {}
    dns_records      = dns_records      or {}
    feeds            = feeds            or []
    case_correlations = case_correlations or []
    comments         = comments         or []
    passive_dns      = passive_dns      or {}
    related_urls     = related_urls     or {}
    related_hashes   = related_hashes   or {}

    # ── Feed Subsets ──────────────────────────────────────────────────────
    tf_entries  = [f for f in feeds if f.get("source", "").lower() == "threatfox"]
    mb_entries  = [f for f in feeds if f.get("source", "").lower() == "malwarebazaar"]
    uh_entries  = [f for f in feeds if f.get("source", "").lower() == "urlhaus"]
    mb_found    = bool(mb_entries)
    uh_found    = bool(uh_entries)

    # ── 1. Unified Risk Score ─────────────────────────────────────────────
    risk_data = scoring.compute_unified_risk_score(
        ioc_type=ioc_type,
        vt_result=vt,
        abuseipdb_result=abuse if ioc_type == "ip" else None,
        otx_result=otx,
        tf_iocs=tf_entries,
        mb_found=mb_found,
        urlhaus_found=uh_found,
        in_watchlist=in_watchlist,
        feed_sightings=len(feeds),
    )

    score      = risk_data["risk_score"]
    components = risk_data.get("components", {})

    # Map internal verdict → display label (strictly 3 levels: Clean, Suspicious, Malicious)
    _map = {
        "Critical": "Malicious",
        "High": "Malicious",
        "High Risk": "Malicious",
        "Medium": "Suspicious",
        "Low": "Suspicious",
        "Clean": "Clean",
        "Malicious": "Malicious",
        "Suspicious": "Suspicious"
    }
    verdict_display = _map.get(risk_data["verdict"], risk_data["verdict"])
    if verdict_display == "Clean":
        score = 0

    _em_map = {"Malicious": "🔴", "Suspicious": "🟡", "Clean": "🟢"}
    level_em = _em_map.get(verdict_display, "⚪")

    # ── 2. Classifications (direct evidence only) ───────────────────────────
    classifications = _detect_classification(vt, feeds, abuse, greynoise)

    # ── 3. Context ─────────────────────────────────────────────────────────
    country      = geo.get("country")      or abuse.get("country_code") or ""
    country_code = geo.get("country_code") or abuse.get("country_code") or ""
    city         = geo.get("city")         or ""
    asn          = geo.get("asn")          or vt.get("asn")            or ""
    isp          = geo.get("isp")          or abuse.get("isp")         or ""
    org          = geo.get("org")          or ""
    usage_type   = abuse.get("usage_type") or ""
    is_tor       = bool(abuse.get("is_tor", False))
    infra_types  = _detect_infra_type(isp, org, usage_type, is_tor)

    # ── 4. RDAP Parsing ────────────────────────────────────────────────────
    if ioc_type == "ip":
        rdap_info = _parse_rdap_ip_info(rdap)
    else:
        rdap_info = rdap if rdap and not rdap.get("error") else {}

    # ── 5. Build Report Parts ─────────────────────────────────────────────
    type_label  = _IOC_TYPE_LABELS.get(ioc_type, ioc_type.upper())
    ioc_display = ioc if len(ioc) <= 48 else ioc[:46] + "…"
    now_str     = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    parts: list[str] = []

    # ═══════════════════════════════════════════════════════════════════════
    # HEADER
    # ═══════════════════════════════════════════════════════════════════════
    parts.append(
        f"<code>{_SEP}</code>\n"
        f"🔍 <b>Threat Intelligence Report</b>\n"
        f"<code>{_SEP}</code>\n\n"
        f"<b>IOC</b>        <code>{_e(ioc_display)}</code>\n"
        f"<b>Type</b>       {_e(type_label)}\n"
    )

    if ioc_type == "ip":
        flag = _flag(country_code)
        loc_parts = [p for p in [city, country] if p]
        if asn:
            parts.append(f"<b>ASN</b>        <code>{_e(str(asn))}</code>\n")
        if org or isp:
            parts.append(f"<b>Org</b>        <code>{_e(org or isp)}</code>\n")
        if loc_parts:
            parts.append(f"<b>Location</b>   {flag} {_e(' | '.join(loc_parts))}\n")
        if infra_types:
            parts.append(f"<b>Infra</b>      <code>{_e(' | '.join(infra_types))}</code>\n")
        if isp and isp not in (org or ""):
            parts.append(f"<b>ISP</b>        <code>{_e(isp)}</code>\n")

    elif ioc_type == "domain":
        registrar = rdap_info.get("registrar") or vt.get("registrar") or ""
        reg_date  = (rdap_info.get("registered") or "")[:10]
        if registrar:
            parts.append(f"<b>Registrar</b>  <code>{_e(registrar)}</code>\n")
        if reg_date:
            parts.append(f"<b>Registered</b> <code>{_e(reg_date)}</code>\n")

    elif ioc_type in ("md5", "sha1", "sha256"):
        file_name = vt.get("file_name") or ""
        file_size = int(vt.get("file_size") or 0)
        magic     = vt.get("magic") or vt.get("type_desc") or ""
        if file_name:
            parts.append(f"<b>File</b>       <code>{_e(file_name[:60])}</code>\n")
        if file_size:
            parts.append(f"<b>Size</b>       <code>{file_size:,} bytes</code>\n")
        if magic:
            parts.append(f"<b>Type</b>       <code>{_e(magic[:60])}</code>\n")

    elif ioc_type == "url":
        final_url = (vt.get("final_url") or "") if vt and not vt.get("error") else ""
        title     = (vt.get("title") or "") if vt and not vt.get("error") else ""
        if title:
            parts.append(f"<b>Title</b>      <i>{_e(title[:80])}</i>\n")
        if final_url and final_url.rstrip('/') != ioc.rstrip('/'):
            parts.append(f"<b>Final URL</b>  <code>{_e(final_url[:60])}</code>\n")

    if from_cache:
        parts.append("\n<i>⚠ Data from cache — live APIs unavailable</i>\n")

    parts.append("\n")

    # ═══════════════════════════════════════════════════════════════════════
    # THREAT ASSESSMENT
    # ═══════════════════════════════════════════════════════════════════════
    parts.append(
        f"<code>{_SEP}</code>\n"
        f"📊 <b>THREAT ASSESSMENT</b>\n"
        f"<code>{_SEP}</code>\n"
        f"<b>Threat Score</b>      <code>{score} / 100</code>\n"
        f"<b>Threat Level</b>      {level_em} <b>{_e(verdict_display)}</b>\n"
    )

    if classifications:
        cls_str = " | ".join(classifications[:4])
        parts.append(f"<b>Classification</b>    <code>{_e(cls_str)}</code>\n")


    parts.append("\n")

    # ═══════════════════════════════════════════════════════════════════════
    # DETECTION SOURCES
    # ═══════════════════════════════════════════════════════════════════════
    parts.append(
        f"<code>{_SEP}</code>\n"
        f"🛡 <b>DETECTION SOURCES</b>\n"
        f"<code>{_SEP}</code>\n"
    )

    # ── VirusTotal ────────────────────────────────────────────────────────
    if vt and not vt.get("error"):
        vt_mal   = int(vt.get("malicious",  0) or 0)
        vt_sus   = int(vt.get("suspicious", 0) or 0)
        vt_harm  = int(vt.get("harmless",   0) or 0)
        vt_undet = int(vt.get("undetected", 0) or 0)
        vt_total = vt_mal + vt_sus + vt_harm + vt_undet

        if vt_total > 0:
            if vt_mal > 0:
                vt_ratio_em = "🔴" if vt_mal >= 5 else "🟠" if vt_mal >= 2 else "🟡"
                vt_status   = f"{vt_ratio_em} {vt_mal} / {vt_total}"
            elif vt_sus > 0:
                vt_status = f"🟡 0 / {vt_total}  ({vt_sus} suspicious)"
            else:
                vt_status = f"🟢 0 / {vt_total}"
        else:
            vt_status = "🟢 No results"

        parts.append(f"<b>VirusTotal</b>     {vt_status}\n")

        # Per-vendor table (Summary + Detections)
        vendor_table = _build_vt_vendor_table(vt)
        if vendor_table:
            parts.append(f"{vendor_table}\n")

        threat_label = str(vt.get("threat_label") or "").strip()
        if threat_label:
            parts.append(f"  <i>Threat Label: {_e(threat_label)}</i>\n")

    elif vt.get("error") if vt else False:
        parts.append("<b>VirusTotal</b>     ⚠ Unavailable\n")

    # ── AbuseIPDB (IP only) ───────────────────────────────────────────────
    if ioc_type == "ip":
        if abuse and not abuse.get("error"):
            ab_score   = int(abuse.get("abuse_score",   0) or 0)
            ab_reports = int(abuse.get("total_reports", 0) or 0)
            is_tor_flag = abuse.get("is_tor", False)
            tor_note = " | Tor Exit Node" if is_tor_flag else ""
            if ab_score == 0 and ab_reports == 0 and not is_tor_flag:
                parts.append(f"<b>AbuseIPDB</b>      🟢 No Reports\n")
            else:
                ab_em = "🔴" if ab_score >= 80 else "🟠" if ab_score >= 30 else "🟡" if ab_score > 0 else "🟢"
                parts.append(
                    f"<b>AbuseIPDB</b>      {ab_em} {ab_score}% confidence | "
                    f"{ab_reports:,} reports{_e(tor_note)}\n"
                )
        elif abuse.get("error") if abuse else False:
            parts.append("<b>AbuseIPDB</b>      ⚠ Unavailable\n")

    # ── AlienVault OTX ──────────────────────────────────────────
    if otx and not otx.get("error"):
        otx_cnt = int(otx.get("pulse_count", 0) or 0)
        if otx_cnt > 0:
            parts.append(f"<b>OTX</b>            Referenced in {otx_cnt} reports\n")
        else:
            parts.append("<b>OTX</b>            No References\n")
    elif otx and otx.get("error"):
        parts.append("<b>OTX</b>            Unavailable\n")
    else:
        parts.append("<b>OTX</b>            No References\n")

    # ── GreyNoise ─────────────────────────────────────────────────────────
    if greynoise and not greynoise.get("error"):
        gn_noise  = greynoise.get("noise", False)
        gn_class  = str(greynoise.get("classification") or "unknown")
        gn_name   = str(greynoise.get("name") or "")
        gn_riot   = greynoise.get("riot", False)

        if gn_riot:
            gn_em, gn_label = "🟢", "RIOT (Trusted Infrastructure)"
        elif gn_class == "malicious":
            gn_em, gn_label = "🔴", "Malicious"
        elif gn_class == "benign":
            gn_em, gn_label = "🟢", "Benign"
        elif gn_noise:
            gn_em, gn_label = "🟡", "Noise"
        else:
            gn_em, gn_label = "⚪", "Unknown"

        gn_name_note = f" | {_e(gn_name)}" if gn_name and gn_name not in ("unknown", "") else ""
        parts.append(f"<b>GreyNoise</b>      {gn_em} {gn_label}{gn_name_note}\n")
    elif greynoise and greynoise.get("error"):
        parts.append("<b>GreyNoise</b>      Not Available\n")

    # ── ThreatFox ─────────────────────────────────────────────────────────
    if tf_entries:
        tf_conf     = max((f.get("confidence", 0) or 0 for f in tf_entries), default=0)
        tf_malware  = next((f.get("threat_category") for f in tf_entries if f.get("threat_category")), "")
        tf_note     = f" | {_e(tf_malware)}" if tf_malware else ""
        parts.append(f"<b>ThreatFox</b>      🔴 Confirmed | Confidence: {tf_conf}%{tf_note}\n")
    else:
        parts.append("<b>ThreatFox</b>      🟢 No Match\n")

    # ── MalwareBazaar ─────────────────────────────────────────────────────
    if mb_entries:
        parts.append("<b>MalwareBazaar</b>  🔴 Confirmed\n")

    # ── URLHaus ───────────────────────────────────────────────────────────
    if uh_entries:
        parts.append("<b>URLHaus</b>        🔴 Confirmed\n")

    # ── Local Threat Feeds ────────────────────────────────────────────────
    other_feeds = [f for f in feeds if f.get("source", "").lower() not in ("threatfox", "malwarebazaar", "urlhaus")]
    if other_feeds:
        feed_src = list({f.get("source", "").upper() for f in other_feeds if f.get("source")})[:5]
        parts.append(f"<b>Threat Feeds</b>   🔴 {', '.join(feed_src)}\n")



    parts.append("\n")

    # ═══════════════════════════════════════════════════════════════════════
    # WHOIS / RDAP
    # ═══════════════════════════════════════════════════════════════════════
    whois_fields: list[tuple[str, str]] = []

    if ioc_type == "ip":
        netname      = rdap_info.get("netname")      or ""
        org_name     = rdap_info.get("organization") or org or ""
        cidr         = rdap_info.get("inetnum")      or str(vt.get("network") or "")
        abuse_email  = rdap_info.get("abuse_contact") or ""
        reg_date     = rdap_info.get("created_date") or ""
        upd_date     = rdap_info.get("updated_date") or ""
        if netname:   whois_fields.append(("Netname",      netname))
        if org_name:  whois_fields.append(("Organization", org_name))
        if cidr:      whois_fields.append(("CIDR",         cidr))
        if country:   whois_fields.append(("Country",      f"{_flag(country_code)} {country}"))
        if abuse_email: whois_fields.append(("Abuse Contact", abuse_email))
        if reg_date:  whois_fields.append(("Registered",   reg_date))
        if upd_date:  whois_fields.append(("Updated",      upd_date))

    elif ioc_type == "domain":
        registrar  = rdap_info.get("registrar")   or str(vt.get("registrar") or "")
        registered = (rdap_info.get("registered") or "")[:10]
        expiry     = (rdap_info.get("expiration") or "")[:10]
        ns_list    = (rdap_info.get("nameservers") or [])[:4]
        status     = rdap_info.get("status") or []
        if registrar:  whois_fields.append(("Registrar",   registrar))
        if registered: whois_fields.append(("Registered",  registered))
        if expiry:     whois_fields.append(("Expires",     expiry))
        if ns_list:    whois_fields.append(("Nameservers", " | ".join(ns_list)))
        if status:     whois_fields.append(("Status",      " | ".join(status[:3])))

    if whois_fields:
        parts.append(
            f"<code>{_SEP}</code>\n"
            f"📋 <b>WHOIS / RDAP</b>\n"
            f"<code>{_SEP}</code>\n"
        )
        for label, value in whois_fields:
            parts.append(f"<b>{_e(label)}</b>    <code>{_e(str(value)[:80])}</code>\n")
        parts.append("\n")

    # ═══════════════════════════════════════════════════════════════════════
    # PASSIVE DNS
    # ═══════════════════════════════════════════════════════════════════════
    if passive_dns and isinstance(passive_dns, dict):
        records = passive_dns.get("records") or []
        if records:
            total_count = len(records)
            limit_records = records[:10]
            
            pdns_lines = [
                f"<code>{_SEP}</code>",
                f"🌐 <b>PASSIVE DNS</b>",
                f"<code>{_SEP}</code>",
                f"Found Domains: {total_count}\n",
                f"<pre>Date         Domain",
                f"────────────────────────────"
            ]
            
            for r in limit_records:
                date_val = r.get("date", "0000-00-00")
                det = r.get("detection", "")
                domain_val = r.get("domain", "")
                if det:
                    row = f"{date_val:<12} {det:<6} {domain_val}"
                else:
                    row = f"{date_val:<12} {domain_val}"
                pdns_lines.append(row)
                
            remaining = total_count - 10
            if remaining > 0:
                pdns_lines.append(f"...and {remaining} more domains.")
                
            pdns_lines.append("</pre>")
            parts.append("\n".join(pdns_lines) + "\n")

    # ═══════════════════════════════════════════════════════════════════════
    # FIRST SEEN / LAST SEEN
    # ═══════════════════════════════════════════════════════════════════════
    first_seen = ""
    last_seen = ""
    if greynoise and greynoise.get("last_seen"):
        last_seen = str(greynoise.get("last_seen"))[:10]
    if otx and otx.get("pulses"):
        created_dates = [p.get("created")[:10] for p in otx.get("pulses") if p.get("created")]
        if created_dates:
            created_dates.sort()
            if not first_seen:
                first_seen = created_dates[0]
            if not last_seen or created_dates[-1] > last_seen:
                last_seen = created_dates[-1]
                
    if first_seen or last_seen:
        seen_lines = [
            f"<code>{_SEP}</code>",
            f"🕒 <b>FIRST SEEN / LAST SEEN</b>",
            f"<code>{_SEP}</code>",
        ]
        if first_seen:
            seen_lines.append(f"<b>First Seen</b>    <code>{first_seen}</code>")
        if last_seen:
            seen_lines.append(f"<b>Last Seen</b>     <code>{last_seen}</code>")
        seen_lines.append("\n")
        parts.append("\n".join(seen_lines))

    # ═══════════════════════════════════════════════════════════════════════
    # THREAT TAGS
    # ═══════════════════════════════════════════════════════════════════════
    tag_set = set()
    for t in vt.get("tags", []):
        tag_set.add(str(t).lower().strip())
    if greynoise:
        if greynoise.get("noise"): tag_set.add("scanner")
        if greynoise.get("riot"): tag_set.add("hosting")
        cls = str(greynoise.get("classification") or "").lower()
        if cls in ("malicious", "benign"):
            tag_set.add(cls)
    for p in otx.get("pulses", []):
        for t in p.get("tags", []):
            tag_set.add(str(t).lower().strip())
            
    tags_whitelist = {"scanner", "vpn", "tor", "malware", "botnet", "c2", "crawler", "proxy", "hosting", "phishing"}
    display_tags = sorted(list({t for t in tag_set if t in tags_whitelist}))
    if display_tags:
        tags_lines = [
            f"<code>{_SEP}</code>",
            f"🏷 <b>THREAT TAGS</b>",
            f"<code>{_SEP}</code>",
            f"<code>{', '.join(display_tags)}</code>\n"
        ]
        parts.append("\n".join(tags_lines))

    # ═══════════════════════════════════════════════════════════════════════
    # RELATED IOCS
    # ═══════════════════════════════════════════════════════════════════════
    related_domains_list = [r.get("domain") for r in (passive_dns.get("records") or []) if r.get("domain")][:5]
    related_urls_list = (related_urls.get("urls") or [])[:5]
    related_hashes_list = (related_hashes.get("hashes") or [])[:5]
    
    if related_domains_list or related_urls_list or related_hashes_list:
        rel_lines = [
            f"<code>{_SEP}</code>",
            f"🔗 <b>RELATED IOCS</b>",
            f"<code>{_SEP}</code>",
        ]
        if related_domains_list:
            rel_lines.append("<b>Domains:</b>")
            for dom in related_domains_list:
                rel_lines.append(f"  • <code>{_e(dom)}</code>")
        if related_urls_list:
            rel_lines.append("<b>URLs:</b>")
            for u in related_urls_list:
                u_disp = u if len(u) <= 45 else u[:42] + "..."
                rel_lines.append(f"  • <code>{_e(u_disp)}</code>")
        if related_hashes_list:
            rel_lines.append("<b>Hashes:</b>")
            for h in related_hashes_list:
                h_disp = h if len(h) <= 45 else h[:42] + "..."
                rel_lines.append(f"  • <code>{_e(h_disp)}</code>")
        rel_lines.append("\n")
        parts.append("\n".join(rel_lines))

    # ═══════════════════════════════════════════════════════════════════════
    # DNS (compact)
    # ═══════════════════════════════════════════════════════════════════════
    if dns_records and ioc_type in ("domain", "url"):
        dns_rows: list[tuple[str, str]] = []
        for ans in (dns_records.get("A") or []):
            if isinstance(ans, dict):
                data_val = str(ans.get("data") or "").strip()
                if data_val:
                    dns_rows.append(("A", data_val))
        for ans in (dns_records.get("MX") or []):
            if isinstance(ans, dict):
                data_val = str(ans.get("data") or "").strip()
                if data_val:
                    dns_rows.append(("MX", data_val))

        if dns_rows:
            parts.append(
                f"<code>{_SEP}</code>\n"
                f"🌐 <b>DNS</b>\n"
                f"<code>{_SEP}</code>\n"
            )
            for rtype, data_val in dns_rows[:3]:
                parts.append(f"<b>{_e(rtype):<5}</b> <code>{_e(data_val[:60])}</code>\n")
            
            remaining = len(dns_rows) - 3
            if remaining > 0:
                parts.append(f"\n<i>(+{remaining} omitted)</i>\n")
            else:
                parts.append("\n")

    # ═══════════════════════════════════════════════════════════════════════
    # PASSIVE INTELLIGENCE
    # Only meaningful extras: rDNS, Open Ports, Hostnames, OS, CVEs
    # (Hosting Type and ISP are already shown in the ASN/header block above)
    # ═══════════════════════════════════════════════════════════════════════
    passive_fields: list[tuple[str, str]] = []

    if ioc_type == "ip":
        # Reverse DNS
        rdns = "N/A"
        try:
            rdns = socket.gethostbyaddr(ioc)[0]
        except Exception:
            pass
        if rdns and rdns != "N/A":
            passive_fields.append(("rDNS", rdns))

        sh_ports     = (shodan.get("ports")     or []) if shodan and not shodan.get("error") else []
        sh_hostnames = (shodan.get("hostnames") or []) if shodan and not shodan.get("error") else []
        sh_os        = (shodan.get("os")        or "") if shodan and not shodan.get("error") else ""
        sh_vulns     = (shodan.get("vulns")     or []) if shodan and not shodan.get("error") else []

        if sh_ports:
            passive_fields.append(("Open Ports", ", ".join(str(p) for p in sh_ports[:12])))
        if sh_hostnames:
            passive_fields.append(("Hostnames",  " | ".join(sh_hostnames[:4])))
        if sh_os:
            passive_fields.append(("OS",         sh_os))
        if sh_vulns:
            passive_fields.append(("CVEs",       ", ".join(str(v) for v in sh_vulns[:5])))
        # Hosting Type and ISP intentionally NOT added here — already in ASN block

    elif ioc_type in ("md5", "sha1", "sha256") and vt and not vt.get("error"):
        md5_val    = vt.get("md5",    "")
        sha1_val   = vt.get("sha1",   "")
        sha256_val = vt.get("sha256", "")
        if md5_val:
            passive_fields.append(("MD5", md5_val))
        if sha1_val:
            passive_fields.append(("SHA1", sha1_val))
        if sha256_val:
            passive_fields.append(("SHA256", sha256_val))

    if passive_fields:
        parts.append(
            f"<code>{_SEP}</code>\n"
            f"🔌 <b>PASSIVE INTELLIGENCE</b>\n"
            f"<code>{_SEP}</code>\n"
        )
        for label, value in passive_fields[:15]:
            parts.append(f"<b>{_e(label)}</b>    <code>{_e(str(value)[:80])}</code>\n")
        parts.append("\n")

    # ═══════════════════════════════════════════════════════════════════════
    # THREAT LABELS  (bullet-point style, security labels only)
    # ═══════════════════════════════════════════════════════════════════════
    final_labels: list[str] = []

    # 1. VT consensus threat label (highest precision)
    vt_label = str(vt.get("threat_label") or "").strip() if vt and not vt.get("error") else ""
    if vt_label:
        final_labels.append(vt_label)

    # 2. Direct feed classifications (ThreatFox, MalwareBazaar, URLHaus)
    for f in feeds:
        src = str(f.get("source") or "").lower().strip()
        if src not in _AUTHORITATIVE_FEED_SOURCES:
            continue
        cat = str(f.get("threat_category") or "").strip()
        if cat:
            cap = cat.replace("_", " ").title()
            if cap.lower() not in [x.lower() for x in final_labels]:
                final_labels.append(cap)

    # 3. Derived classifications (filtered — no generic non-security labels)
    for c in classifications:
        cap = c.replace("_", " ").title()
        if cap.lower() not in [x.lower() for x in final_labels]:
            final_labels.append(cap)

    if final_labels:
        parts.append(
            f"<code>{_SEP}</code>\n"
            f"\U0001f3f7 <b>THREAT LABELS</b>\n"
            f"<code>{_SEP}</code>\n"
        )
        for lbl in final_labels[:6]:
            parts.append(f"  \u2022 {_e(lbl)}\n")
        parts.append("\n")

    parts.append(f"<i>TI-Bot | UTC {now_str}</i>")

    # ── Result dict (for DB caching) ──────────────────────────────────────
    result = {
        "risk_level":         verdict_display,
        "threat_score":       score,
        "vt_malicious":       int(vt.get("malicious",  0) or 0) if vt and not vt.get("error") else 0,
        "abuse_score":        int(abuse.get("abuse_score", 0) or 0) if abuse and not abuse.get("error") else 0,
        "otx_pulses":         int(otx.get("pulse_count", 0) or 0) if otx and not otx.get("error") else 0,
        "country":            country,
        "asn":                str(asn),
        "soc_verdict":        verdict_display,
        "soc_risk_score":     score,
        "soc_confidence":     risk_data.get("confidence", 50),
        "soc_action":         "MONITOR",      # kept for DB schema compatibility only
        "soc_sources_active": list(components.keys()),
        "classifications":    classifications,
        "passive_dns_count":  len(passive_dns.get("records") or []) if passive_dns else 0,
    }

    return "".join(parts), result
