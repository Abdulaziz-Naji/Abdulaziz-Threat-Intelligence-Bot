"""
ioc_risk_scoring.py - Phase 3.7 Unified IOC Risk Scoring Model

Combines signals from all available intelligence sources into a single
normalised risk score (0-100) with confidence and verdict label.

Sources weighted:
  - VirusTotal:       detections / total → up to 40 pts
  - AbuseIPDB:        abuse_score        → up to 25 pts
  - OTX:              pulse_count        → up to 15 pts
  - ThreatFox:        confidence level   → up to 10 pts
  - MalwareBazaar:    presence           → up to 5 pts
  - URLHaus:          presence           → up to 5 pts
  - Watchlist bonus:                       +10 pts
  - Feed sightings:   count × 2          → up to 10 pts (capped)

Output:
  {
    "risk_score":   int (0-100),
    "verdict":      str  ("Clean" | "Low" | "Medium" | "High" | "Critical"),
    "verdict_em":   str  emoji,
    "confidence":   int (0-100),
    "components":   dict of per-source contributions,
    "recommendation": str,
  }
"""

from typing import Optional


# ═══════════════════════════════════════════════════════════════════════════════
#  Source Signal Extractors
# ═══════════════════════════════════════════════════════════════════════════════

def _vt_score(vt: Optional[dict]) -> tuple[int, str]:
    """VirusTotal: (pts, note)."""
    if not vt or "error" in vt:
        return 0, "unavailable"
    malicious  = vt.get("malicious", 0) or 0
    suspicious = vt.get("suspicious", 0) or 0
    harmless   = vt.get("harmless", 0) or 0
    undetected = vt.get("undetected", 0) or 0
    total = malicious + suspicious + harmless + undetected
    if total == 0:
        return 0, "no results"
    # Ratio of malicious/suspicious to total
    ratio = (malicious + suspicious * 0.5) / total
    pts = int(ratio * 40)
    # Bonus for very high malicious count
    if malicious >= 50:
        pts = min(pts + 5, 40)
    return min(pts, 40), f"{malicious}/{total} detections"


def _abuseipdb_score(aipdb: Optional[dict]) -> tuple[int, str]:
    """AbuseIPDB: (pts, note). Only applicable for IPs."""
    if not aipdb or "error" in aipdb:
        return 0, "unavailable"
    score = aipdb.get("abuse_score", 0) or 0
    pts   = int(score * 0.25)  # max 100 × 0.25 = 25
    return min(pts, 25), f"abuse confidence {score}%"


def _otx_score(otx: Optional[dict]) -> tuple[int, str]:
    """OTX: (pts, note).
    
    OTX is an evidence source only.
    It must NOT increase the Threat Score simply because an IOC appears inside OTX Pulses.
    Only allow OTX to contribute to the Threat Score if the Pulse explicitly classifies the IOC itself
    as Malware, Phishing, C2, Botnet, Ransomware, Exploit.
    """
    if not otx or "error" in otx or not isinstance(otx, dict):
        return 0, "unavailable"

    pulses = otx.get("pulses") or []
    if not pulses:
        return 0, "0 classified OTX pulses"

    keywords = {"malware", "phishing", "c2", "c&c", "command and control", "botnet", "ransomware", "exploit"}
    qualifying_pulses = 0

    for p in pulses:
        if not isinstance(p, dict):
            continue
        name = str(p.get("name") or "").lower()
        desc = str(p.get("description") or "").lower()
        tags = [str(t).lower() for t in (p.get("tags") or []) if t]

        matched = False
        for kw in keywords:
            if kw in name or kw in desc or any(kw in t for t in tags):
                matched = True
                break
        if matched:
            qualifying_pulses += 1

    if qualifying_pulses > 0:
        pts = min(qualifying_pulses * 3, 15)
        return pts, f"{qualifying_pulses} classified OTX pulse(s)"

    return 0, "0 classified OTX pulses"


def _threatfox_score(tf_iocs: Optional[list]) -> tuple[int, str]:
    """ThreatFox: (pts, note)."""
    if not tf_iocs:
        return 0, "not found"
    max_confidence = max((e.get("confidence", 0) or 0) for e in tf_iocs)
    pts = int(max_confidence * 0.10)  # confidence 0-100 → 0-10 pts
    return min(pts, 10), f"max confidence {max_confidence}%"


def _feed_sightings_score(feed_count: int) -> tuple[int, str]:
    """Local feed sightings: (pts, note)."""
    pts = min(feed_count * 2, 10)
    return pts, f"{feed_count} feed sighting(s)"


def _mb_score(mb_found: bool) -> tuple[int, str]:
    """MalwareBazaar presence: (pts, note)."""
    return (5, "found in MalwareBazaar") if mb_found else (0, "not found")


def _urlhaus_score(urlhaus_found: bool) -> tuple[int, str]:
    """URLHaus presence: (pts, note)."""
    return (5, "found in URLHaus") if urlhaus_found else (0, "not found")


def _watchlist_bonus(in_watchlist: bool) -> tuple[int, str]:
    """Watchlist bonus."""
    return (10, "on watchlist") if in_watchlist else (0, "not on watchlist")


# ═══════════════════════════════════════════════════════════════════════════════
#  Verdict Labels
# ═══════════════════════════════════════════════════════════════════════════════

def _verdict(score: int) -> tuple[str, str]:
    """Return (verdict_label, emoji)."""
    if score >= 50:
        return "Malicious", "🔴"
    if score >= 25:
        return "Suspicious", "🟡"
    return "Clean", "🟢"



# ═══════════════════════════════════════════════════════════════════════════════
#  Confidence Calculator
# ═══════════════════════════════════════════════════════════════════════════════

def _confidence(sources_contributing: int, feed_count: int, vt_available: bool) -> int:
    """Estimate confidence based on how many sources contributed non-zero signals."""
    base = sources_contributing * 15
    if vt_available:
        base += 10
    if feed_count > 0:
        base += min(feed_count * 3, 10)
    return min(base, 100)


# ═══════════════════════════════════════════════════════════════════════════════
#  Main Scoring Function
# ═══════════════════════════════════════════════════════════════════════════════

def compute_unified_risk_score(
    ioc_type: str,
    vt_result:        Optional[dict] = None,
    abuseipdb_result: Optional[dict] = None,
    otx_result:       Optional[dict] = None,
    tf_iocs:          Optional[list] = None,
    mb_found:         bool = False,
    urlhaus_found:    bool = False,
    in_watchlist:     bool = False,
    feed_sightings:   int  = 0,
) -> dict:
    """
    Compute a unified risk score from multiple intelligence sources.

    Args:
        ioc_type:         "ip" | "domain" | "url" | "md5" | "sha1" | "sha256"
        vt_result:        VirusTotal API response dict
        abuseipdb_result: AbuseIPDB API response dict (IPs only)
        otx_result:       OTX API response dict
        tf_iocs:          List of ThreatFox IOC entries
        mb_found:         Whether hash was found in MalwareBazaar
        urlhaus_found:    Whether IOC was found in URLHaus
        in_watchlist:     Whether IOC is in the local watchlist
        feed_sightings:   Count of local feed database hits

    Returns:
        Unified risk profile dict.
    """
    components = {}
    total_pts  = 0
    contributing = 0

    # ── VirusTotal ──────────────────────────────────────────────────────────
    vt_pts, vt_note = _vt_score(vt_result)
    components["VirusTotal"]     = {"points": vt_pts, "note": vt_note}
    total_pts += vt_pts
    if vt_pts > 0:
        contributing += 1
    vt_available = vt_result is not None and "error" not in (vt_result or {})

    # ── AbuseIPDB (IP only) ────────────────────────────────────────────────
    if ioc_type == "ip":
        ab_pts, ab_note = _abuseipdb_score(abuseipdb_result)
        components["AbuseIPDB"] = {"points": ab_pts, "note": ab_note}
        total_pts += ab_pts
        if ab_pts > 0:
            contributing += 1

    # ── OTX ───────────────────────────────────────────────────────────────
    otx_pts, otx_note = _otx_score(otx_result)
    components["OTX"]            = {"points": otx_pts, "note": otx_note}
    total_pts += otx_pts
    if otx_pts > 0:
        contributing += 1

    # ── ThreatFox ─────────────────────────────────────────────────────────
    tf_pts, tf_note = _threatfox_score(tf_iocs)
    components["ThreatFox"]      = {"points": tf_pts, "note": tf_note}
    total_pts += tf_pts
    if tf_pts > 0:
        contributing += 1

    # ── MalwareBazaar ─────────────────────────────────────────────────────
    mb_pts, mb_note = _mb_score(mb_found)
    components["MalwareBazaar"]  = {"points": mb_pts, "note": mb_note}
    total_pts += mb_pts
    if mb_pts > 0:
        contributing += 1

    # ── URLHaus ───────────────────────────────────────────────────────────
    uh_pts, uh_note = _urlhaus_score(urlhaus_found)
    components["URLHaus"]        = {"points": uh_pts, "note": uh_note}
    total_pts += uh_pts
    if uh_pts > 0:
        contributing += 1

    # ── Feed Sightings ────────────────────────────────────────────────────
    fd_pts, fd_note = _feed_sightings_score(feed_sightings)
    components["FeedSightings"]  = {"points": fd_pts, "note": fd_note}
    total_pts += fd_pts
    if fd_pts > 0:
        contributing += 1

    # ── Watchlist Bonus ───────────────────────────────────────────────────
    wl_pts, wl_note = _watchlist_bonus(in_watchlist)
    components["Watchlist"]      = {"points": wl_pts, "note": wl_note}
    total_pts += wl_pts

    risk_score = min(total_pts, 100)

    # ── VirusTotal Override Rules ──────────────────────────────────────────
    if vt_available and vt_result and "error" not in vt_result:
        vt_mal = int(vt_result.get("malicious", 0) or 0)
        vt_sus = int(vt_result.get("suspicious", 0) or 0)
        vt_det = vt_mal + vt_sus
        
        vt_harmless = int(vt_result.get("harmless", 0) or 0)
        vt_undetected = int(vt_result.get("undetected", 0) or 0)
        vt_tot = vt_mal + vt_sus + vt_harmless + vt_undetected

        if vt_det >= 2:
            # Must be Malicious (score 50-100)
            risk_score = max(50 + min(vt_det * 3, 50), risk_score)
            risk_score = min(risk_score, 100)
        elif vt_det == 1:
            # Must be Suspicious (score 25-49)
            risk_score = max(25, min(risk_score, 49))

    verdict, verdict_em = _verdict(risk_score)
    confidence = _confidence(contributing, feed_sightings, vt_available)

    return {
        "risk_score":   risk_score,
        "verdict":      verdict,
        "verdict_em":   verdict_em,
        "confidence":   confidence,
        "components":   components,
        "sources_hit":  contributing,
    }


def format_risk_breakdown(scoring: dict) -> str:
    """Format the risk scoring breakdown as an HTML Telegram block."""
    parts = [f"📊 <b>Unified Risk Score: <code>{scoring['risk_score']}/100</code></b> {scoring['verdict_em']} <b>{scoring['verdict']}</b>\n"]
    parts.append(f"🔬 <b>Confidence:</b> <code>{scoring['confidence']}%</code>\n\n")
    parts.append("<b>📋 Score Breakdown:</b>\n")
    for source, data in scoring["components"].items():
        pts  = data["points"]
        note = data["note"]
        bar  = "█" * (pts // 4) if pts > 0 else "░"
        parts.append(f"  • <b>{source}:</b> <code>+{pts:2d}</code> {bar} <i>{note}</i>\n")
    return "".join(parts)
