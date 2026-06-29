"""
decision_engine.py - Final SOC Decision Engine.

Accepts raw intelligence signals from all sources and produces a
deterministic FinalDecision. Always outputs a verdict — never fails.

Weighting:
  VirusTotal  50%
  AbuseIPDB   25%
  OTX         15%
  Feeds       10%
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List


# ─── Data model ───────────────────────────────────────────────────────────────

@dataclass
class FinalDecision:
    ioc:        str
    ioc_type:   str
    risk_score: int          # 0–100  (weighted composite)
    confidence: int          # 0–100%
    verdict:    str          # Clean / Suspicious / High Risk / Malicious
    action:     str          # ALLOW / MONITOR / INVESTIGATE / BLOCK / ISOLATE
    action_em:  str          # emoji for action
    verdict_em: str          # emoji for verdict
    reasons:    List[str]    # bullet points explaining decision
    mode:       str          # FULL / PARTIAL / FALLBACK / CACHE_ONLY
    sources_active: List[str]  # which sources contributed
    evidence_count: int = 1
    threat_feed_count: int = 0
    fp_probability: float = 0.0
    source_reliability: str = "Medium"
    correlation_score: int = 0
    evidence_score: int = 0
    reasoning_score: int = 90
    threat_intel_score: int = 0


# ─── Thresholds ───────────────────────────────────────────────────────────────

_VERDICT_MAP = [
    (75, "Malicious", "🔴", "BLOCK",        "🛑"),
    (45, "High Risk", "🟠", "BLOCK",        "🛑"),
    (15, "Suspicious", "🟡", "MONITOR",      "👁"),
    ( 0, "Clean",     "🟢", "ALLOW",        "✅"),
]


def _verdict_from_score(score: int):
    for threshold, verdict, v_em, action, a_em in _VERDICT_MAP:
        if score >= threshold:
            return verdict, v_em, action, a_em
    return "Clean", "🟢", "ALLOW", "✅"


# ─── False Positive Classifier ────────────────────────────────────────────────

_FP_DOMAINS = frozenset({
    "ns.adobe.com", "purl.org", "cipa.jp", "iptc.org", "color.org",
    "creativecommons.org", "xmp.icc", "adobe.com", "www.w3.org", "w3.org", 
    "xml.org", "xmlsoap.org", "schemas.openxmlformats.org", "schemas.microsoft.com",
    "purl.oclc.org", "schemas.xmlsoap.org", "example.com", "example.org", 
    "example.net", "localhost", "localdomain", "apache.org", "maven.apache.org", "gradle.org"
})

_FP_DLLS = frozenset({
    "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll", "ws2_32.dll", 
    "msvcrt.dll", "ole32.dll", "shell32.dll", "gdi32.dll", "comctl32.dll", 
    "comdlg32.dll", "shlwapi.dll", "wininet.dll", "winhttp.dll", "crypt32.dll", 
    "bcrypt.dll", "secur32.dll", "netapi32.dll", "iphlpapi.dll", "psapi.dll", 
    "dbghelp.dll", "version.dll", "imagehlp.dll", "winspool.drv", "msvcp140.dll", 
    "vcruntime140.dll", "ucrtbase.dll", "ntoskrnl.exe", "hal.dll", "win32k.sys"
})


def _compute_fp_probability(ioc: str, ioc_type: str) -> float:
    """Assess if the IOC is a known false positive (Adobe, W3C, System DLLs, etc.)."""
    v = ioc.strip().lower()
    
    if ioc_type == "domain":
        if v in _FP_DOMAINS or any(v.endswith("." + d) for d in _FP_DOMAINS):
            return 0.99
        if v in _FP_DLLS:
            return 0.95
    elif ioc_type == "url":
        if any(d in v for d in _FP_DOMAINS) or "w3.org" in v or "adobe.com" in v or "openxmlformats.org" in v or "schemas.microsoft.com" in v:
            return 0.99
    elif ioc_type in ("pe", "file", "generic") and v in _FP_DLLS:
        return 0.95
    return 0.0


# ─── Weighted score computation ───────────────────────────────────────────────

def _weighted_score(
    vt_malicious:  int = 0,
    vt_suspicious: int = 0,
    vt_total:      int = 0,   # total VT engines scanned
    abuse_score:   int = 0,
    otx_pulses:    int = 0,
    feed_risk:     int = 0,
) -> int:
    """Returns a 0–100 weighted composite score."""
    if vt_total > 0:
        vt_ratio = (vt_malicious / vt_total) * 100
    else:
        vt_ratio = min(vt_malicious * 5 + vt_suspicious * 2, 100)
    vt_component = vt_ratio * 0.50

    abuse_component = (abuse_score / 100) * 100 * 0.25
    otx_component = min(otx_pulses / 30, 1.0) * 100 * 0.15
    feed_component = (feed_risk / 100) * 100 * 0.10

    return min(int(vt_component + abuse_component + otx_component + feed_component), 100)


def _confidence_from_sources(sources: list[str], fp_prob: float) -> int:
    """Calculate confidence based on source counts, penalized by false positive probability."""
    pts = 0
    sl = [s.lower() for s in sources]
    if any("virustotal" in s for s in sl):
        pts += 40
    if any("abuseipdb" in s for s in sl):
        pts += 25
    if any("otx" in s for s in sl):
        pts += 20
    if any("feed" in s or "malwarebazaar" in s or "threatfox" in s
           or "urlhaus" in s or "feodo" in s for s in sl):
        pts += 10
    if any("cache" in s for s in sl):
        pts += 5
        
    confidence = min(pts, 100)
    if fp_prob > 0.5:
        confidence = int(confidence * (1.0 - fp_prob))
    return max(5, confidence)


# ─── Reason bullet builder ────────────────────────────────────────────────────

def _build_reasons(
    vt_malicious:  int,
    vt_suspicious: int,
    vt_total:      int,
    vt_label:      str,
    abuse_score:   int,
    is_tor:        bool,
    otx_pulses:    int,
    feed_sources:  list,
    in_watchlist:  bool,
    from_cache:    bool,
    ioc_type:      str,
    fp_prob:       float,
) -> list[str]:
    reasons = []

    if fp_prob > 0.5:
        reasons.append(f"Indicator identified as common false positive / standard metadata (FP Probability: {fp_prob*100:.0f}%)")
        return reasons

    # VT
    if vt_malicious > 0:
        vt_of = f"/{vt_total}" if vt_total else ""
        reasons.append(
            f"VirusTotal: {vt_malicious}{vt_of} engines detected as malicious"
            + (f" ({vt_label})" if vt_label else "")
        )
    elif vt_suspicious > 0:
        reasons.append(f"VirusTotal: {vt_suspicious} engines flagged as suspicious")

    # AbuseIPDB
    if abuse_score >= 80:
        tor_note = " — TOR Exit Node" if is_tor else ""
        reasons.append(f"AbuseIPDB: Abuse score {abuse_score}/100{tor_note}")
    elif abuse_score > 0:
        reasons.append(f"AbuseIPDB: Abuse score {abuse_score}/100")

    # OTX
    if otx_pulses > 0:
        reasons.append(f"OTX AlienVault: {otx_pulses} threat intelligence pulse(s)")

    # Feeds
    if feed_sources:
        src_names = list({s.get("source", "Unknown").upper() for s in feed_sources})[:3]
        reasons.append(f"Threat Feeds: Observed in {', '.join(src_names)}")

    # Watchlist
    if in_watchlist:
        reasons.append("Indicator is actively monitored on watchlist")

    if from_cache and not (vt_malicious or vt_suspicious or abuse_score or otx_pulses):
        reasons.append("Decision based on historical enrichment cache")

    if not reasons:
        reasons.append("Insufficient intelligence data — no active threat indicators observed")

    return reasons


# ─── Determine operating mode ─────────────────────────────────────────────────

def _determine_mode(sources_active: list[str], from_cache: bool) -> str:
    live_sources = [s for s in sources_active if s != "Cache"]
    if not live_sources:
        if from_cache:
            return "CACHE_ONLY"
        return "FALLBACK"
    if len(live_sources) >= 2:
        return "FULL"
    return "PARTIAL"


# ─── Main public API ──────────────────────────────────────────────────────────

def make_decision(
    ioc:           str,
    ioc_type:      str,
    *,
    vt_malicious:  int = 0,
    vt_suspicious: int = 0,
    vt_total:      int = 0,
    vt_label:      str = "",
    abuse_score:   int = 0,
    is_tor:        bool = False,
    otx_pulses:    int = 0,
    feed_sources:  list = None,   # list of dicts from get_ioc_all_sources
    in_watchlist:  bool = False,
    from_cache:    bool = False,
    cache_risk:    int  = 0,
    vt_available:  bool = True,
    abuse_available: bool = True,
    otx_available:  bool = True,
    correlation_score: int = 0,
    yara_malicious: bool = False,
    sig_valid:     bool = False,
    sig_valid_conflict: bool = False,
    suspicious_imports: bool = False,
    greynoise_benign: bool = False,
    ocr_secret:    bool = False,
    photoshop_metadata: bool = False,
    high_entropy:  bool = False,
    gps_coordinates: bool = False,
    hidden_executable: bool = False,
) -> FinalDecision:
    """Primary decision function. Always returns a FinalDecision."""
    feed_sources = feed_sources or []
    feed_risk = max((s.get("risk_score", 0) or 0 for s in feed_sources), default=0)

    # 1. FP Probability
    fp_prob = _compute_fp_probability(ioc, ioc_type)

    # 2. Weighted composite score
    score = _weighted_score(
        vt_malicious=vt_malicious,
        vt_suspicious=vt_suspicious,
        vt_total=vt_total,
        abuse_score=abuse_score,
        otx_pulses=otx_pulses,
        feed_risk=feed_risk,
    )

    if score == 0 and from_cache and cache_risk > 0:
        score = max(int(cache_risk * 0.6), 0)

    # Incorporate evidence weights into risk score (Phase 9)
    extra_score = 0
    if yara_malicious: extra_score += 30
    if hidden_executable: extra_score += 30
    if ocr_secret: extra_score += 15
    if suspicious_imports: extra_score += 15
    if photoshop_metadata: extra_score += 5
    if high_entropy: extra_score += 2
    
    score = min(score + extra_score, 100)

    # 3. Active Sources & Reliability
    sources_active = []
    if vt_available and (vt_malicious > 0 or vt_suspicious > 0 or vt_total > 0):
        sources_active.append("VirusTotal")
    if abuse_available and ioc_type == "ip" and (abuse_score > 0 or vt_available):
        sources_active.append("AbuseIPDB")
    if otx_available and otx_pulses > 0:
        sources_active.append("OTX")
    if feed_sources:
        sources_active.append("Threat Feeds")
    if from_cache:
        sources_active.append("Cache")

    sources_active = list(dict.fromkeys(sources_active))

    # Calculate advanced metrics
    reliability_scores = []
    if vt_malicious > 0: reliability_scores.append(0.9)
    if abuse_score > 0: reliability_scores.append(0.85)
    if otx_pulses > 0: reliability_scores.append(0.8)
    if feed_sources: reliability_scores.append(0.8)
    if from_cache: reliability_scores.append(0.5)
    
    avg_rel = sum(reliability_scores) / len(reliability_scores) if reliability_scores else 0.5
    source_reliability = "High" if avg_rel >= 0.8 else "Medium" if avg_rel >= 0.6 else "Low"
    evidence_count = max(1, vt_malicious + (1 if abuse_score > 0 else 0) + otx_pulses + len(feed_sources))
    threat_feed_count = len(feed_sources)

    # 4. Confidence
    confidence = _confidence_from_sources(sources_active, fp_prob)
    if correlation_score > 0:
        confidence = min(confidence + int(correlation_score * 0.3), 100) # boost confidence on correlation!
    if from_cache and not (vt_available or abuse_available or otx_available):
        confidence = min(confidence + 5, 35)

    # 5. Verdict and action
    verdict, verdict_em, action, action_em = _verdict_from_score(score)

    # 6. Apply IP threat feeds agreement rules
    if ioc_type == "ip":
        flagged_sources = []
        if vt_malicious >= 2:
            flagged_sources.append("VirusTotal")
        if abuse_score >= 20:
            flagged_sources.append("AbuseIPDB")
        if otx_pulses > 0:
            flagged_sources.append("OTX")
        if feed_sources:
            flagged_sources.append("Threat Feeds")
            
        if len(flagged_sources) >= 2:
            # Multiple feeds agree!
            score = max(score, 75)
            verdict = "Malicious"
            action = "BLOCK"
            verdict_em = "🔴"
            action_em = "🛑"
        elif len(flagged_sources) == 1:
            # Only one flags!
            score = min(score, 30) # force to suspicious
            verdict = "Suspicious"
            action = "MONITOR"
            verdict_em = "🟡"
            action_em = "👁"
        else:
            score = 0
            verdict = "Clean"
            action = "ALLOW"
            verdict_em = "🟢"
            action_em = "✅"

    # 7. Apply Smart FP Prioritization
    if fp_prob > 0.8:
        score = 0
        verdict = "Clean"
        action = "ALLOW"
        verdict_em = "🟢"
        action_em = "✅"

    # 8. Contradiction Engine
    contradictions = []
    # Conflict 1: VirusTotal clean vs. YARA malicious
    if vt_available and vt_total > 0 and vt_malicious == 0 and yara_malicious:
        contradictions.append(
            "Contradiction: VirusTotal reports clean, but local YARA analysis detected malicious signature(s)."
        )

    # Conflict 2: Valid Digital Signature vs. Suspicious Imports/Behavior
    if (sig_valid or sig_valid_conflict) and (suspicious_imports or yara_malicious or vt_malicious > 0 or sig_valid_conflict):
        contradictions.append(
            "Contradiction: File has a valid/trusted digital signature, but contains suspicious process injection or persistence API imports."
        )

    # Conflict 3: IP flagged by one source but clean in GreyNoise / multiple other feeds
    # Check if there is exactly 1 flagged source from VT, AbuseIPDB, OTX, or threat feeds, and GreyNoise benign is True
    ti_flagged_count = 0
    if vt_malicious > 0: ti_flagged_count += 1
    if abuse_score > 0: ti_flagged_count += 1
    if otx_pulses > 0: ti_flagged_count += 1
    if feed_sources: ti_flagged_count += 1

    if greynoise_benign and ti_flagged_count == 1:
        contradictions.append(
            "Contradiction: IP flagged as suspicious by one feed, but GreyNoise classifies it as a benign/common Internet scanner."
        )

    # If contradictions are found, set verdict to "Mixed Evidence", penalize confidence, and update action
    if contradictions:
        verdict = "Mixed Evidence"
        verdict_em = "🟡"
        action = "MONITOR"
        action_em = "👁"
        confidence = max(5, int(confidence * 0.8))

    # Calculate dashboard scores
    vt_ratio = 0
    if vt_total > 0:
        vt_ratio = (vt_malicious / vt_total) * 100
    else:
        vt_ratio = min(vt_malicious * 5 + vt_suspicious * 2, 100)
    
    threat_intel_score = min(max(vt_ratio, abuse_score, min(otx_pulses * 20, 100), feed_risk), 100)

    total_weight = 0
    if vt_malicious > 0: total_weight += 30
    if yara_malicious: total_weight += 30
    if hidden_executable: total_weight += 30
    if ocr_secret: total_weight += 15
    if suspicious_imports: total_weight += 15
    if photoshop_metadata: total_weight += 5
    if high_entropy: total_weight += 2
    if abuse_score > 0: total_weight += min(abuse_score * 0.3, 30)
    if otx_pulses > 0: total_weight += min(otx_pulses * 5, 20)
    if feed_sources: total_weight += 15
    evidence_score = min(int(total_weight), 100)

    base_reasoning = 85
    if correlation_score > 0:
        base_reasoning += min(int(correlation_score * 0.2), 15)
    if contradictions:
        base_reasoning -= 20 * len(contradictions)
    reasoning_score = max(0, min(base_reasoning, 100))

    reasons = _build_reasons(
        vt_malicious=vt_malicious,
        vt_suspicious=vt_suspicious,
        vt_total=vt_total,
        vt_label=vt_label,
        abuse_score=abuse_score,
        is_tor=is_tor,
        otx_pulses=otx_pulses,
        feed_sources=feed_sources,
        in_watchlist=in_watchlist,
        from_cache=from_cache,
        ioc_type=ioc_type,
        fp_prob=fp_prob,
    )
    
    # Append contradictions to reasons list
    for contra in contradictions:
        reasons.append(contra)

    mode = _determine_mode(sources_active, from_cache)

    return FinalDecision(
        ioc=ioc,
        ioc_type=ioc_type,
        risk_score=score,
        confidence=confidence,
        verdict=verdict,
        action=action,
        action_em=action_em,
        verdict_em=verdict_em,
        reasons=reasons,
        mode=mode,
        sources_active=sources_active,
        evidence_count=evidence_count,
        threat_feed_count=threat_feed_count,
        fp_probability=fp_prob,
        source_reliability=source_reliability,
        correlation_score=correlation_score,
        evidence_score=evidence_score,
        reasoning_score=reasoning_score,
        threat_intel_score=threat_intel_score,
    )


def fuse_from_correlation(ioc: str, ioc_type: str, corr: dict) -> FinalDecision:
    """Build a FinalDecision from a correlation engine result dict."""
    enrichment   = corr.get("_enrichment_raw", {}) or {}
    live_srcs    = corr.get("live_intelligence_sources", [])
    feed_sources = corr.get("observed_sources", [])
    in_watchlist = corr.get("in_watchlist", False)

    vt_mal   = enrichment.get("vt_malicious", 0) or 0
    ab_score = enrichment.get("abuse_score", 0) or 0
    otx_cnt  = enrichment.get("otx_pulses", 0) or 0
    cache_risk = enrichment.get("risk_score", 0) or 0
    from_cache = bool(enrichment)

    vt_avail    = "VirusTotal" in live_srcs
    abuse_avail = "AbuseIPDB" in live_srcs
    otx_avail   = "OTX" in live_srcs

    # Compute case-wide correlation score
    correlation_score = 0
    related_count = len(corr.get("related_ips", [])) + len(corr.get("related_domains", []))
    if related_count >= 3:
        correlation_score = 100
    elif related_count == 2:
        correlation_score = 70
    elif related_count == 1:
        correlation_score = 40

    return make_decision(
        ioc=ioc,
        ioc_type=ioc_type,
        vt_malicious=vt_mal,
        vt_suspicious=0,
        vt_total=0,
        abuse_score=ab_score,
        otx_pulses=otx_cnt,
        feed_sources=feed_sources,
        in_watchlist=in_watchlist,
        from_cache=from_cache,
        cache_risk=cache_risk,
        vt_available=vt_avail,
        abuse_available=abuse_avail,
        otx_available=otx_avail,
        correlation_score=correlation_score,
    )



