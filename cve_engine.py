"""
cve_engine.py - Phase 3.5 CVE Intelligence Engine

Queries:
  1. NVD (NIST) API v2 for CVE details, CVSS v3 score
  2. CISA KEV feed to check active exploitation status
  3. EPSS (Exploit Prediction Scoring System) for exploitation probability

Usage:
    result = await lookup_cve("CVE-2021-44228")
"""
import asyncio
import httpx
from typing import Optional
import re


# ═══════════════════════════════════════════════════════════════════════════════
#  NVD API v2
# ═══════════════════════════════════════════════════════════════════════════════

async def _query_nvd(cve_id: str) -> dict:
    """Query NVD API v2 for CVE details."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
            r = await client.get(url, headers={"Accept": "application/json"})
        if r.status_code != 200:
            return {"error": f"NVD HTTP {r.status_code}"}
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {"found": False}
        cve_data = vulns[0].get("cve", {})
        metrics   = cve_data.get("metrics", {})

        # CVSS v3.1 primary
        cvss_score   = None
        cvss_vector  = ""
        cvss_severity = ""
        cvss_v31 = metrics.get("cvssMetricV31", [])
        if cvss_v31:
            primary = next((m for m in cvss_v31 if m.get("type") == "Primary"), cvss_v31[0])
            cvss_data = primary.get("cvssData", {})
            cvss_score    = cvss_data.get("baseScore")
            cvss_vector   = cvss_data.get("vectorString", "")
            cvss_severity = cvss_data.get("baseSeverity", "")

        # CVSS v3.0 fallback
        if cvss_score is None:
            cvss_v30 = metrics.get("cvssMetricV30", [])
            if cvss_v30:
                primary = next((m for m in cvss_v30 if m.get("type") == "Primary"), cvss_v30[0])
                cvss_data = primary.get("cvssData", {})
                cvss_score    = cvss_data.get("baseScore")
                cvss_vector   = cvss_data.get("vectorString", "")
                cvss_severity = cvss_data.get("baseSeverity", "")

        # CVSS v2 fallback
        if cvss_score is None:
            cvss_v2 = metrics.get("cvssMetricV2", [])
            if cvss_v2:
                primary = next((m for m in cvss_v2 if m.get("type") == "Primary"), cvss_v2[0])
                cvss_data = primary.get("cvssData", {})
                cvss_score    = cvss_data.get("baseScore")
                cvss_severity = primary.get("baseSeverity", "")
                cvss_vector   = cvss_data.get("vectorString", "")

        # Description
        descriptions = cve_data.get("descriptions", [])
        description  = ""
        for d in descriptions:
            if d.get("lang") == "en":
                description = d.get("value", "")
                break

        # CWE
        weaknesses = cve_data.get("weaknesses", [])
        cwes = []
        for w in weaknesses:
            for desc in w.get("description", []):
                cwe = desc.get("value", "")
                if cwe.startswith("CWE-") and cwe not in cwes:
                    cwes.append(cwe)

        # CPE / affected products
        configs = cve_data.get("configurations", [])
        affected_products = []
        for config in configs[:2]:
            for node in config.get("nodes", [])[:2]:
                for cpe in node.get("cpeMatch", [])[:3]:
                    criteria = cpe.get("criteria", "")
                    if criteria:
                        # Parse cpe:2.3:a:vendor:product:version
                        parts = criteria.split(":")
                        if len(parts) >= 5:
                            vendor  = parts[3]
                            product = parts[4]
                            version = parts[5] if len(parts) > 5 else "*"
                            label = f"{vendor} {product}" + (f" {version}" if version not in ("*", "-") else "")
                            if label not in affected_products:
                                affected_products.append(label)

        # References
        references = []
        for ref in cve_data.get("references", [])[:3]:
            url_r = ref.get("url", "")
            if url_r:
                references.append(url_r)

        published  = cve_data.get("published", "")[:10]
        modified   = cve_data.get("lastModified", "")[:10]

        return {
            "found":            True,
            "cve_id":           cve_data.get("id", cve_id),
            "description":      description[:500] if description else "",
            "cvss_score":       cvss_score,
            "cvss_severity":    cvss_severity,
            "cvss_vector":      cvss_vector,
            "cwes":             cwes[:3],
            "affected":         affected_products[:5],
            "references":       references,
            "published":        published,
            "modified":         modified,
        }
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
#  EPSS (Exploit Prediction Scoring System)
# ═══════════════════════════════════════════════════════════════════════════════

async def _query_epss(cve_id: str) -> dict:
    """Query EPSS API for exploitation probability score."""
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            r = await client.get(
                f"https://api.first.org/data/v1/epss?cve={cve_id}"
            )
        if r.status_code != 200:
            return {"error": f"EPSS HTTP {r.status_code}"}
        data = r.json()
        items = data.get("data", [])
        if not items:
            return {"found": False}
        item = items[0]
        return {
            "found":      True,
            "epss_score": float(item.get("epss", 0)),
            "percentile": float(item.get("percentile", 0)),
            "date":       item.get("date", ""),
        }
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
#  CISA KEV Check
# ═══════════════════════════════════════════════════════════════════════════════

_KEV_CACHE: Optional[list] = None

async def _check_cisa_kev(cve_id: str) -> dict:
    """Check if CVE is in CISA Known Exploited Vulnerabilities catalog."""
    global _KEV_CACHE
    try:
        if _KEV_CACHE is None:
            async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
                r = await client.get(
                    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
                )
            if r.status_code == 200:
                _KEV_CACHE = r.json().get("vulnerabilities", [])
            else:
                _KEV_CACHE = []

        for vuln in (_KEV_CACHE or []):
            if vuln.get("cveID", "").upper() == cve_id.upper():
                return {
                    "in_kev":           True,
                    "vendor_project":   vuln.get("vendorProject", ""),
                    "product":          vuln.get("product", ""),
                    "kev_name":         vuln.get("vulnerabilityName", ""),
                    "date_added":       vuln.get("dateAdded", ""),
                    "due_date":         vuln.get("dueDate", ""),
                    "required_action":  vuln.get("requiredAction", ""),
                    "known_ransomware": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                }
        return {"in_kev": False}
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
#  Main CVE Lookup
# ═══════════════════════════════════════════════════════════════════════════════

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def is_valid_cve(text: str) -> bool:
    """Return True if text looks like a CVE ID."""
    return bool(_CVE_RE.match(text.strip()))


def _cvss_emoji(score: Optional[float]) -> str:
    if score is None:
        return "⚪"
    if score >= 9.0:
        return "🔴"
    if score >= 7.0:
        return "🟠"
    if score >= 4.0:
        return "🟡"
    return "🟢"


async def lookup_cve(cve_id: str) -> dict:
    """
    Full CVE intelligence lookup.
    Combines NVD, EPSS, and CISA KEV data.
    Returns unified profile dict.
    """
    cve_id = cve_id.strip().upper()

    # Parallel queries
    nvd_task  = _query_nvd(cve_id)
    epss_task = _query_epss(cve_id)
    kev_task  = _check_cisa_kev(cve_id)

    nvd, epss, kev = await asyncio.gather(nvd_task, epss_task, kev_task)

    profile = {
        "cve_id":             cve_id,
        "found":              nvd.get("found", False),
        "description":        nvd.get("description", ""),
        "cvss_score":         nvd.get("cvss_score"),
        "cvss_severity":      nvd.get("cvss_severity", ""),
        "cvss_vector":        nvd.get("cvss_vector", ""),
        "cvss_emoji":         _cvss_emoji(nvd.get("cvss_score")),
        "cwes":               nvd.get("cwes", []),
        "affected":           nvd.get("affected", []),
        "references":         nvd.get("references", []),
        "published":          nvd.get("published", ""),
        "modified":           nvd.get("modified", ""),
        # EPSS
        "epss_score":         epss.get("epss_score", 0.0) if epss.get("found") else None,
        "epss_percentile":    epss.get("percentile", 0.0) if epss.get("found") else None,
        # CISA KEV
        "in_kev":             kev.get("in_kev", False),
        "kev_data":           kev if kev.get("in_kev") else {},
        # NVD error passthrough
        "_nvd_error":         nvd.get("error", ""),
    }
    return profile


def format_cve_report(profile: dict) -> str:
    """Format a CVE profile as HTML for Telegram."""
    sep   = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
    cve_id = profile["cve_id"]
    cvss   = profile.get("cvss_score")
    em     = profile.get("cvss_emoji", "⚪")
    sev    = profile.get("cvss_severity", "Unknown")

    if not profile.get("found"):
        err = profile.get("_nvd_error", "")
        return (
            f"❌ <b>CVE not found in NVD database.</b>\n"
            f"<code>{cve_id}</code>\n"
            + (f"\n<i>{err}</i>" if err else "")
        )

    # KEV badge
    kev_badge = ""
    if profile.get("in_kev"):
        kev = profile.get("kev_data", {})
        ransomware = kev.get("known_ransomware", "Unknown")
        kev_badge = (
            f"\n🚨 <b>CISA KEV:</b> <b>YES — Actively Exploited!</b>\n"
            f"   📋 {kev.get('kev_name', '')}\n"
            f"   📅 Added: <code>{kev.get('date_added', 'N/A')}</code>\n"
            f"   🦠 Ransomware Use: <b>{ransomware}</b>\n"
            f"   🔧 Action: <i>{kev.get('required_action', 'N/A')[:100]}</i>\n"
        )
    else:
        kev_badge = "\n✅ <b>CISA KEV:</b> Not in KEV catalog\n"

    # EPSS
    epss_str = ""
    if profile.get("epss_score") is not None:
        pct = int((profile["epss_percentile"] or 0) * 100)
        epss_str = (
            f"📊 <b>EPSS Score:</b> <code>{profile['epss_score']:.4f}</code> "
            f"(top <b>{100 - pct}%</b> exploitation probability)\n"
        )

    # Affected
    affected_str = ""
    if profile.get("affected"):
        affected_str = "💻 <b>Affected:</b> <i>" + ", ".join(profile["affected"][:4]) + "</i>\n"

    # CWEs
    cwe_str = ""
    if profile.get("cwes"):
        cwe_str = "🔑 <b>Weakness:</b> <code>" + ", ".join(profile["cwes"]) + "</code>\n"

    # Description (truncated)
    desc = profile.get("description", "")
    if len(desc) > 300:
        desc = desc[:297] + "…"

    nvd_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    report = (
        f"🔓 <b>CVE Intelligence Report</b>\n"
        f"<code>{sep}</code>\n\n"
        f"🆔 <b>CVE ID:</b> <code>{cve_id}</code>\n"
        f"📅 <b>Published:</b> <code>{profile.get('published', 'N/A')}</code>\n"
        f"{em} <b>CVSS Score:</b> <code>{cvss if cvss is not None else 'N/A'}</code> — <b>{sev}</b>\n"
        f"{epss_str}"
        f"{kev_badge}\n"
        f"{cwe_str}"
        f"{affected_str}\n"
        f"📝 <b>Description:</b>\n<i>{desc}</i>\n\n"
        f"🔗 <a href=\"{nvd_link}\">View on NVD</a>\n"
        f"<code>{sep}</code>"
    )
    return report
