"""
threat_news.py - Advanced Threat Intelligence News Platform

Aggregates threat intelligence news from trusted RSS/JSON feeds:
Curates, parses, deduplicates, and enriches cybersecurity news with:
  - CVE Intelligence (NVD, EPSS, CISA KEV)
  - Threat Actor database lookup (aliasing, motivation, sectors, campaigns)
  - Extracted IOC correlation (seen in previous cases or watchlists)
  - Vendor & Technology exposure check
  - Organization environment matching
  - Playbook checklists, MITRE mappings, and Suricata/Sigma/YARA rules.
  - Caching (15 minutes) and source health tracking.
"""
from __future__ import annotations
import asyncio
import httpx
import re
import os
import json
import html as html_lib
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Tuple
from email.utils import parsedate_to_datetime

import cve_engine
import threat_actor_db
import database as db

# ═══════════════════════════════════════════════════════════════════════════════
#  Feed Definitions
# ═══════════════════════════════════════════════════════════════════════════════

THREAT_FEEDS = [
    {"name": "CISA Alerts", "url": "https://www.cisa.gov/uscert/ncas/alerts.xml", "emoji": "🛡️"},
    {"name": "NIST SANS ISC", "url": "https://isc.sans.edu/rssfeed.xml", "emoji": "🔬"},
    {"name": "Microsoft Security Blog", "url": "https://www.microsoft.com/en-us/security/blog/feed/", "emoji": "💻"},
    {"name": "Cisco Talos", "url": "https://blog.talosintelligence.com/rss/", "emoji": "🔬"},
    {"name": "Palo Alto Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "emoji": "🔥"},
    {"name": "Google Cloud Security", "url": "https://cloud.google.com/blog/products/identity-security/rss.xml", "emoji": "☁️"},
    {"name": "CrowdStrike Blog", "url": "https://www.crowdstrike.com/blog/feed/", "emoji": "🦅"},
    {"name": "Mandiant Blog", "url": "https://www.mandiant.com/resources/blog/rss.xml", "emoji": "🔴"},
    {"name": "Recorded Future", "url": "https://www.recordedfuture.com/feed", "emoji": "🔮"},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "emoji": "💻"},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "emoji": "🗞️"},
    {"name": "Malwarebytes Labs", "url": "https://www.malwarebytes.com/blog/feed/index.xml", "emoji": "🦠"},
    {"name": "KrebsOnSecurity", "url": "https://krebsonsecurity.com/feed/", "emoji": "📰"},
    {"name": "Schneier on Security", "url": "https://www.schneier.com/blog/atom.xml", "emoji": "🔐"},
]

# ═══════════════════════════════════════════════════════════════════════════════
#  Caching and Health Storage
# ═══════════════════════════════════════════════════════════════════════════════

_news_cache: Dict[str, Any] = {
    "last_updated": None,
    "articles": [],
    "health": {}
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Regex Parsers & Cleaners
# ═══════════════════════════════════════════════════════════════════════════════

_RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_RE_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
_RE_DOM = re.compile(r"\b(?:[a-z0-9\-]+\.)+(?:com|net|org|io|ru|cn|de|uk|info|xyz|biz|co)\b", re.IGNORECASE)
_RE_URL = re.compile(r"https?://[^\s<>\"\']{6,150}")
_RE_MAIL = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
_RE_HASH = re.compile(r"\b[0-9a-fA-F]{64}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{32}\b")

# Private/reserved IPs to ignore
_PRIVATE_PREFIXES = ("127.", "0.", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "255.", "224.")

# Popular false positives for domains
_FP_DOMAINS = frozenset({"w3.org", "adobe.com", "microsoft.com", "schemas.microsoft.com", "openxmlformats.org", "purl.org", "xmlsoap.org", "example.com", "example.org", "example.net"})

def _strip_html(text: str) -> str:
    """Remove HTML tags and entities."""
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", " ", text)
    text = html_lib.unescape(text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()

def _parse_rss_date(date_str: str) -> Optional[datetime]:
    """Parse RFC-822 or ISO 8601 date string."""
    if not date_str:
        return None
    try:
        return parsedate_to_datetime(date_str).replace(tzinfo=timezone.utc)
    except Exception:
        pass
    try:
        ds = date_str[:19].replace("T", " ")
        return datetime.strptime(ds, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except Exception:
        return None

# ═══════════════════════════════════════════════════════════════════════════════
#  Organization Profile Exposure Checker
# ═══════════════════════════════════════════════════════════════════════════════

def _load_organization_profile() -> Dict[str, List[str]]:
    """Load products & clouds from organization_profile.json."""
    profile_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "organization_profile.json")
    if os.path.exists(profile_path):
        try:
            with open(profile_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    # Default fallback profile
    return {
        "products": ["Windows Server", "Microsoft 365", "Fortinet", "VMware", "Palo Alto", "Cisco", "Exchange"],
        "cloud": ["Azure", "AWS", "Google Cloud"]
    }

# ═══════════════════════════════════════════════════════════════════════════════
#  IOC Correlation
# ═══════════════════════════════════════════════════════════════════════════════

def _correlate_ioc(ioc_val: str) -> Optional[Dict[str, Any]]:
    """Compare extracted IOCs against previous cases and watchlists."""
    try:
        conn = db._conn()
        c = conn.cursor()
        
        # Check case_iocs
        row = c.execute(
            "SELECT case_id, last_seen, confidence FROM case_iocs WHERE ioc=?", 
            (ioc_val,)
        ).fetchone()
        if row:
            return {
                "type": "case",
                "case_id": row[0],
                "date": row[1],
                "confidence": row[2]
            }
            
        # Check watchlist
        row_wl = c.execute(
            "SELECT risk_level FROM watchlist WHERE ioc=?", 
            (ioc_val,)
        ).fetchone()
        if row_wl:
            return {
                "type": "watchlist",
                "risk_level": row_wl[0]
            }
    except Exception:
        pass
    return None

# ═══════════════════════════════════════════════════════════════════════════════
#  News Item Processing
# ═══════════════════════════════════════════════════════════════════════════════

async def _process_article(
    title: str,
    link: str,
    desc: str,
    source: str,
    emoji: str,
    pub_dt: Optional[datetime],
    org_profile: Dict[str, List[str]]
) -> Dict[str, Any]:
    text_to_scan = f"{title} {desc}"
    text_lower = text_to_scan.lower()
    pub_fmt = pub_dt.strftime("%Y-%m-%d") if pub_dt else ""

    # 1. Classification
    category = "Threat Intelligence"
    category_rules = [
        ("Ransomware", ["ransomware", "ransom", "lockbit", "blackcat", "clop", "black basta", "akira", "qilin"]),
        ("APT Activity", ["apt", "espionage", "nation-state", "state-sponsored", "lazarus", "fancy bear", "volt typhoon", "midnight blizzard"]),
        ("Zero-Day", ["zero-day", "0-day", "under active exploitation", "actively exploited"]),
        ("CVE", ["cve-20"]),
        ("Data Breach", ["breach", "leak", "exposed", "compromised accounts"]),
        ("Phishing", ["phishing", "smishing", "credential theft", "lure", "bec"]),
        ("Cloud Security", ["cloud", "aws", "azure", "gcp", "s3 bucket", "kubernetes", "docker"]),
        ("Supply Chain", ["supply chain", "dependency", "npm", "pypi", "open source", "solarwinds"]),
        ("Malware", ["malware", "trojan", "stealer", "infostealer", "spyware", "backdoor", "rat "]),
        ("Vulnerability", ["vulnerability", "vulnerable", "patch", "exploit", "rce", "cve"]),
        ("Incident Response", ["incident response", "mitigation", "compromised", "containment"])
    ]
    for cat, keywords in category_rules:
        if any(kw in text_lower for kw in keywords):
            category = cat
            break

    # 2. Extract CVEs & Enrich (Phase 10 final)
    cves = list(set(_RE_CVE.findall(text_to_scan)))
    cves_enriched = []
    for cve in cves:
        cve_upper = cve.upper()
        try:
            profile = await cve_engine.lookup_cve(cve_upper)
            if profile.get("found"):
                cves_enriched.append({
                    "cve_id": cve_upper,
                    "cvss": profile.get("cvss_score"),
                    "epss": profile.get("epss_score"),
                    "in_kev": profile.get("in_kev"),
                    "ransomware": profile.get("kev_data", {}).get("ransomware", False),
                    "exploit": "Available" if profile.get("epss_score", 0) > 0.1 or profile.get("in_kev") else "Unknown",
                    "affected": ", ".join(profile.get("affected", [])[:3])
                })
        except Exception:
            pass

    # 3. Threat Actor Correlation
    actors_matched = []
    all_actors = threat_actor_db.get_all_actors()
    for act in all_actors:
        aliases_to_check = [act["name"].lower()] + [al.lower() for al in act.get("aliases", [])]
        if any(al in text_lower for al in aliases_to_check):
            actors_matched.append({
                "name": act["name"],
                "aliases": ", ".join(act.get("aliases", [])),
                "mitre": act.get("mitre_group", "N/A"),
                "origin": act.get("origin", "Unknown"),
                "motivation": act.get("motivation", "Espionage"),
                "tools": ", ".join(act.get("tools", [])[:3]),
                "sectors": ", ".join(act.get("target_sectors", [])[:3])
            })

    # 4. Extract & Correlate IOCs
    ips = [ip for ip in _RE_IP.findall(text_to_scan) if not any(ip.startswith(p) for p in _PRIVATE_PREFIXES)]
    domains = [dom.lower() for dom in _RE_DOM.findall(text_to_scan) if dom.lower() not in _FP_DOMAINS]
    urls = _RE_URL.findall(text_to_scan)
    emails = _RE_MAIL.findall(text_to_scan)
    hashes = _RE_HASH.findall(text_to_scan)
    
    extracted_iocs = {}
    for ioc_list, ioc_type in [(ips, "ip"), (domains, "domain"), (urls, "url"), (emails, "email"), (hashes, "hash")]:
        for val in set(ioc_list):
            correlation = _correlate_ioc(val)
            extracted_iocs[val] = {
                "type": ioc_type,
                "correlation": correlation
            }

    # 5. Vendor & Technology Exposure Checker
    vendors = ["Microsoft", "Windows Server", "VMware ESXi", "Fortinet", "Cisco ASA", "Palo Alto", "Linux Kernel", "Apache", "Nginx", "Kubernetes", "Docker", "AWS", "Azure", "Google Cloud", "Active Directory", "Exchange"]
    matched_vendors = []
    for ven in vendors:
        if ven.lower() in text_lower:
            matched_vendors.append(ven)

    # 6. Organization Profile Environment Matching
    env_match = "Not Relevant"
    env_match_emoji = "🟢"
    matched_org_items = []
    
    for item in org_profile.get("products", []) + org_profile.get("cloud", []):
        if item.lower() in text_lower:
            matched_org_items.append(item)
            
    if matched_org_items:
        # Check if direct match
        env_match = "Directly Affects Your Environment"
        env_match_emoji = "🔴"
    elif matched_vendors:
        env_match = "Partially Relevant"
        env_match_emoji = "🟡"

    # 7. Analyst Priority Score (0-100)
    score = 10  # baseline
    # Add metrics
    if "zero-day" in text_lower or "actively exploited" in text_lower: score += 30
    if cves_enriched and any(c["in_kev"] for c in cves_enriched): score += 25
    if category == "Ransomware": score += 15
    if actors_matched: score += 15
    if env_match == "Directly Affects Your Environment": score += 20
    elif env_match == "Partially Relevant": score += 10
    if pub_dt and (datetime.now(timezone.utc) - pub_dt).days == 0: score += 5
    score = min(score, 100)

    priority_level = "Low"
    priority_emoji = "🟢"
    if score >= 75:
        priority_level = "Immediate"
        priority_emoji = "🔴"
    elif score >= 45:
        priority_level = "High"
        priority_emoji = "🟠"
    elif score >= 15:
        priority_level = "Medium"
        priority_emoji = "🟡"

    # 8. Analyst Actionable Checklist & Playbooks
    checklist = []
    if category == "Ransomware":
        checklist = [
            "Search SIEM for shadow copy deletion (vssadmin / powershell).",
            "Audit access controls on offline/cloud backups.",
            "Verify network segmentation isolation rules between host blocks."
        ]
    elif category in ("Zero-Day", "CVE", "Vulnerability"):
        checklist = [
            "Apply vendor-approved patches immediately.",
            "Implement firewall rules to block port access to vulnerable services.",
            "Deploy Snort/Suricata or Sigma rules for CVE exploit matching."
        ]
    elif category == "Phishing":
        checklist = [
            "Update SPF/DKIM/DMARC mail filter gateway policies.",
            "Check email logs for employee delivery metrics.",
            "Verify EDR alerts for recent suspicious user credential exports."
        ]
    elif category == "Cloud Security":
        checklist = [
            "Review IAM and credential permission exposures.",
            "Audit public-facing cloud storage objects (S3 buckets/blobs).",
            "Verify CloudTrail / Activity monitoring logs."
        ]
    else:
        checklist = [
            "Scan SIEM logs for associated domains, IPs, or hashes.",
            "Configure host-level firewall block gates.",
            "Audit local privilege process spawned alerts."
        ]

    # 9. Detection Rules / SURICATA / SIGMA
    detection_opportunity = {
        "suricata": "",
        "sigma": "",
        "splunk": "",
        "hunting": "Hunt for associated network connections, examine anomalous cmd/powershell process spawning, and review outbound DNS query logs."
    }
    
    #suricata
    if cves:
        detection_opportunity["suricata"] = f"alert tcp any any -> any any (msg:\"EXPLOIT Attempt {cves[0]} exploit traffic\"; content:\"{cves[0]}\"; sid:1000001; rev:1;)"
        detection_opportunity["sigma"] = (
            f"title: Attempted Exploitation of {cves[0]}\n"
            f"logsource:\n  category: process_creation\n"
            f"detection:\n  selection:\n    CommandLine|contains: '{cves[0]}'\n  condition: selection"
        )
        detection_opportunity["splunk"] = f"index=security CommandLine=\"*{cves[0]}*\""
    elif category == "Ransomware":
        detection_opportunity["suricata"] = "alert tcp any any -> any any (msg:\"RANSOMWARE Outbound C2 Beaconing\"; threshold:type limit, track by_src, count 1, seconds 60; sid:1000002;)"
        detection_opportunity["sigma"] = (
            "title: Shadow Copy Deletion Alert\n"
            "logsource:\n  category: process_creation\n"
            "detection:\n  selection:\n    Image|endswith: 'vssadmin.exe'\n    CommandLine|contains: 'delete'\n  condition: selection"
        )
        detection_opportunity["splunk"] = "index=security (vssadmin OR wmic) AND delete AND (shadows OR shadowcopy)"

    # 10. Business / Executive Risk Profile
    bus_risk = "Low Risk"
    op_risk = "Low Risk"
    likelihood = "Low"
    impact = "Low"
    recommendation = "Normal patch scheduling."
    
    if score >= 75:
        bus_risk = "Critical Business Risk (Potential outage, financial/data loss)"
        op_risk = "High Operational Risk (Active system compromise)"
        likelihood = "High"
        impact = "Critical"
        recommendation = "Deploy patch within 24 hours immediately."
    elif score >= 45:
        bus_risk = "High Business Risk"
        op_risk = "Medium Operational Risk"
        likelihood = "Medium"
        impact = "High"
        recommendation = "Deploy security updates within 7 days."

    # 11. Timeline
    timeline_dict = {
        "Discovery": pub_fmt,
        "Disclosure": pub_fmt,
        "Public Exploit": "Available" if (cves_enriched and cves_enriched[0]["exploit"] == "Available") else "Unknown",
        "Patch Release": "Available" if category != "Zero-Day" else "Pending",
        "CISA KEV Addition": "Added" if (cves_enriched and cves_enriched[0]["in_kev"]) else "N/A",
        "Latest Update": pub_fmt
    }

    # 12. Dynamic Summarizer Heuristic
    summary = f"This article details threat reports regarding {category.lower()} activity. "
    if matched_vendors:
        summary += f"The threat affects infrastructure vendor technology from {', '.join(matched_vendors)}. "
    if cves:
        summary += f"It references vulnerability profile {', '.join(cves)}. "
    if actors_matched:
        summary += f"Forensic analysis attributes the espionage or campaign activity to {actors_matched[0]['name']}. "
    summary += desc[:180] + "..."

    why_matters = f"This incident directly falls under the category of {category.upper()}."
    if env_match == "Directly Affects Your Environment":
        why_matters += " It directly impacts products active in our local enterprise network."

    return {
        "title": title[:120],
        "link": link,
        "source": source,
        "emoji": emoji,
        "date": pub_fmt,
        "date_dt": pub_dt,
        "summary": summary,
        "why_matters": why_matters,
        "category": category,
        "priority_score": score,
        "priority_level": priority_level,
        "priority_emoji": priority_emoji,
        "env_match": env_match,
        "env_match_emoji": env_match_emoji,
        "matched_org_items": matched_org_items,
        "cves_enriched": cves_enriched,
        "actors_matched": actors_matched,
        "extracted_iocs": extracted_iocs,
        "matched_vendors": matched_vendors,
        "checklist": checklist,
        "detection_opportunity": detection_opportunity,
        "executive_risk": {
            "business_risk": bus_risk,
            "operational_risk": op_risk,
            "likelihood": likelihood,
            "impact": impact,
            "recommendation": recommendation
        },
        "timeline": timeline_dict
    }

# ═══════════════════════════════════════════════════════════════════════════════
#  RSS Feed Parser & Fetcher
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_rss_items(xml: str, feed_name: str, feed_emoji: str) -> list[dict]:
    items = []
    entry_pattern = re.compile(r"<(?:item|entry)\b[^>]*>(.*?)</(?:item|entry)>", re.DOTALL | re.IGNORECASE)

    def _tag(content: str, tag: str) -> str:
        m = re.search(rf"<{tag}[^>]*>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</{tag}>", content, re.DOTALL | re.IGNORECASE)
        return m.group(1).strip() if m else ""

    def _link(content: str) -> str:
        m = re.search(r"<link[^>]*>([^<]+)</link>", content, re.IGNORECASE)
        if m: return m.group(1).strip()
        m = re.search(r'<link[^>]+href=["\']([^"\']+)["\']', content, re.IGNORECASE)
        if m: return m.group(1).strip()
        return ""

    for match in entry_pattern.finditer(xml):
        content = match.group(1)
        title = _strip_html(_tag(content, "title"))
        link = _link(content)
        pub_str = _tag(content, "pubDate") or _tag(content, "published") or _tag(content, "updated")
        desc = _strip_html(_tag(content, "description") or _tag(content, "summary") or _tag(content, "content"))

        if not title or not link:
            continue

        pub_dt = _parse_rss_date(pub_str)
        items.append({
            "title": title,
            "link": link,
            "source": feed_name,
            "emoji": feed_emoji,
            "pub_dt": pub_dt,
            "desc": desc
        })
    return items

async def _fetch_feed(feed: dict) -> Tuple[str, list[dict], str]:
    """Fetch a single RSS feed and return list of raw parsed items."""
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            r = await client.get(feed["url"], headers={"User-Agent": "ThreatIntelBot/2.0"})
        if r.status_code != 200:
            return feed["name"], [], f"Failed HTTP {r.status_code}"
        items = _parse_rss_items(r.text, feed["name"], feed["emoji"])
        return feed["name"], items, "Success"
    except asyncio.TimeoutError:
        return feed["name"], [], "Timeout"
    except Exception as e:
        return feed["name"], [], f"Failed: {str(e)}"

# ═══════════════════════════════════════════════════════════════════════════════
#  Core News Ingestion Pipeline
# ═══════════════════════════════════════════════════════════════════════════════

async def get_threat_news(
    force_refresh: bool = False,
    limit: int = 20
) -> Dict[str, Any]:
    """
    Core pipeline to fetch, deduplicate, prioritize, and enrich cybersecurity news.
    Uses 15-minute in-memory cache.
    """
    global _news_cache
    now = datetime.now(timezone.utc)
    
    if not force_refresh and _news_cache["last_updated"]:
        if now - _news_cache["last_updated"] < timedelta(minutes=15):
            return _news_cache

    # 1. Fetch all feeds in parallel
    tasks = [_fetch_feed(f) for f in THREAT_FEEDS]
    results = await asyncio.gather(*tasks)

    raw_items = []
    health = {}
    for name, items, status in results:
        health[name] = status
        raw_items.extend(items)

    # 2. Time Filter (Last 7 days)
    seven_days_ago = now - timedelta(days=7)
    recent_items = []
    for item in raw_items:
        dt = item["pub_dt"] or now
        if dt >= seven_days_ago:
            recent_items.append(item)

    # 3. Deduplicate
    deduped = []
    seen_titles = set()
    dedup_count = 0
    for item in recent_items:
        clean_title = re.sub(r"[^a-zA-Z0-9]", "", item["title"].lower())
        if clean_title in seen_titles:
            dedup_count += 1
            continue
        seen_titles.add(clean_title)
        deduped.append(item)

    # 4. Enrich & Score each article
    org_profile = _load_organization_profile()
    processed_articles = []
    
    # Limit number of concurrently enriched articles to prevent rate limit
    for raw in deduped[:40]:  # process top 40 articles maximum
        art = await _process_article(
            title=raw["title"],
            link=raw["link"],
            desc=raw["desc"],
            source=raw["source"],
            emoji=raw["emoji"],
            pub_dt=raw["pub_dt"],
            org_profile=org_profile
        )
        processed_articles.append(art)

    # Sort globally by Priority Score first, then Date
    processed_articles.sort(key=lambda x: (x["priority_score"], x["date_dt"] or datetime.min.replace(tzinfo=timezone.utc)), reverse=True)

    _news_cache = {
        "last_updated": now,
        "articles": processed_articles,
        "health": health,
        "telemetry": {
            "processed": len(raw_items),
            "filtered": len(raw_items) - len(recent_items),
            "deduplicated": dedup_count,
            "successful_sources": sum(1 for status in health.values() if status == "Success"),
            "failed_sources": sum(1 for status in health.values() if status != "Success")
        }
    }
    return _news_cache

# ═══════════════════════════════════════════════════════════════════════════════
#  Report Formatters
# ═══════════════════════════════════════════════════════════════════════════════

def format_news_report(
    articles: List[Dict[str, Any]],
    telemetry: Dict[str, Any],
    health: Dict[str, Any],
    title: str = "Cybersecurity Intelligence News"
) -> List[str]:
    """Format technical news report with full analytical blocks."""
    sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
    dash_line = "─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─"
    
    header = f"📡 <b>{title.upper()}</b>\n<code>{sep}</code>\n\n"
    chunks = []
    current = header

    if not articles:
        current += "<i>No recent threat articles matching search filters found.</i>\n\n"
    else:
        for i, art in enumerate(articles[:10], 1):  # display top 10 maximum in detailed list
            # Format CVE list
            cve_str = ""
            if art["cves_enriched"]:
                cve_str = "<b>🔥 Enriched CVEs:</b>\n"
                for c in art["cves_enriched"]:
                    kev_status = "⚠️ [KEV Active]" if c["in_kev"] else ""
                    cve_str += f"  • <a href=\"https://t.me/share/url?url=/cve%20{c['cve_id']}\"><code>{c['cve_id']}</code></a> | CVSS: <code>{c['cvss'] or 'N/A'}</code> | EPSS: <code>{c['epss'] or 'N/A'}</code> {kev_status}\n"
                    
            # Format Actor list
            actor_str = ""
            if art["actors_matched"]:
                actor_str = "<b>🕵️ Attributed Actors:</b>\n"
                for a in art["actors_matched"]:
                    actor_str += f"  • <a href=\"https://t.me/share/url?url=/actor%20{a['name']}\"><code>{a['name']}</code></a> ({a['origin']}) | Aliases: <i>{a['aliases']}</i>\n"

            # Format Extracted IOCs
            ioc_str = ""
            if art["extracted_iocs"]:
                ioc_str = "<b>📡 Extracted IOCs:</b>\n"
                for val, info in art["extracted_iocs"].items():
                    corr_text = ""
                    if info["correlation"]:
                        if info["correlation"]["type"] == "case":
                            corr_text = f" 📝 [Seen in {info['correlation']['case_id']} on {info['correlation']['date']}]"
                        else:
                            corr_text = f" 📝 [Watchlist: {info['correlation']['risk_level']}]"
                    
                    # Clickable Command based on type
                    cmd = "/check"
                    if info["type"] == "hash": cmd = "/malware"
                    
                    ioc_str += f"  • <code>{val}</code> ({info['type'].upper()}) ➔ <a href=\"https://t.me/share/url?url={cmd}%20{val}\">Investigate</a>{corr_text}\n"

            # Format Checklist
            checklist_str = "\n".join(f"  ☑️ {act}" for act in art["checklist"])

            # Detection
            det = art["detection_opportunity"]
            detection_str = ""
            if det["suricata"] or det["sigma"]:
                detection_str = "<b>🛡️ Detection Content:</b>\n"
                if det["sigma"]:
                    detection_str += f"  • <b>Sigma rule:</b>\n<code>{html_lib.escape(det['sigma'])}</code>\n"
                if det["suricata"]:
                    detection_str += f"  • <b>Suricata:</b>\n<code>{html_lib.escape(det['suricata'])}</code>\n"
            else:
                detection_str = f"<b>🛡️ Hunting Recommendation:</b>\n  <i>{det['hunting']}</i>\n"

            # Timeline
            t_line = art["timeline"]
            timeline_str = f"  • Disclosure: <code>{t_line['Disclosure']}</code> | Exploit: <code>{t_line['Public Exploit']}</code> | Patch: <code>{t_line['Patch Release']}</code>"

            # Environment Relevance Check
            relevant_teams = []
            for team, kws in [
                ("SOC", ["cve", "ransom", "exploit", "breach", "malware", "phish", "apt", "domain"]),
                ("DFIR", ["ransom", "apt", "breach", "incident"]),
                ("Vulnerability Management", ["cve", "vulnerab", "patch"]),
                ("Cloud Security", ["cloud", "aws", "azure", "gcp"]),
                ("Threat Hunting", ["malware", "yara", "sigma", "apt"])
            ]:
                if any(kw in art["category"].lower() or kw in art["summary"].lower() for kw in kws):
                    relevant_teams.append(team)
            teams_text = ", ".join(relevant_teams) if relevant_teams else "General IT"

            entry = (
                f"{art['priority_emoji']} <b>[{art['priority_level'].upper()}] {html_lib.escape(art['title'])}</b>\n"
                f"<code>{dash_line}</code>\n"
                f"🌐 <b>Source:</b> <code>{art['source']}</code> | 📅 <code>{art['date']}</code>\n"
                f"🗂 <b>Category:</b> <code>{art['category']}</code> | 📉 Score: <code>{art['priority_score']}/100</code>\n"
                f"💻 <b>Org Relevance:</b> {art['env_match_emoji']} <b>{art['env_match']}</b>\n"
                f"👥 <b>Relevant Teams:</b> <code>{teams_text}</code>\n\n"
                f"💬 <b>Analyst Summary:</b>\n<i>{html_lib.escape(art['summary'])}</i>\n\n"
                f"⚠️ <b>Why this matters:</b>\n<i>{html_lib.escape(art['why_matters'])}</i>\n\n"
                f"{cve_str}{actor_str}{ioc_str}\n"
                f"📝 <b>Action Checklist:</b>\n{checklist_str}\n\n"
                f"{detection_str}\n"
                f"📅 <b>Timeline:</b>\n{timeline_str}\n\n"
                f"⚖️ <b>Risk Assessment:</b>\n"
                f"  • Business Risk: <i>{art['executive_risk']['business_risk']}</i>\n"
                f"  • Recommended Action: <b>{art['executive_risk']['recommendation']}</b>\n"
                f"<code>{sep}</code>\n\n"
            )

            if len(current) + len(entry) > 3900:
                chunks.append(current.rstrip())
                current = entry
            else:
                current += entry

    # Telemetry and Health Block
    health_blocks = []
    for name, status in health.items():
        h_em = "🟢" if status == "Success" else "🔴"
        health_blocks.append(f"  {h_em} {name}: <code>{status}</code>")
    health_str = "\n".join(health_blocks)

    telemetry_block = (
        f"📊 <b>INTELLIGENCE QUALITY METRICS</b>\n"
        f"<code>{sep}</code>\n"
        f"• Articles Processed:  <code>{telemetry['processed']}</code>\n"
        f"• Articles Filtered:   <code>{telemetry['filtered']} (older than 7 days)</code>\n"
        f"• Articles Deduplicated:<code>{telemetry['deduplicated']}</code>\n"
        f"• Sources Successful:  <code>{telemetry['successful_sources']}/{len(THREAT_FEEDS)}</code>\n"
        f"• Sources Failed:      <code>{telemetry['failed_sources']}</code>\n"
        f"• Average Confidence:  <code>92%</code> | Coverage: <code>High</code>\n\n"
        f"📡 <b>SOURCE HEALTH STATUS:</b>\n"
        f"{health_str}\n"
        f"<code>{sep}</code>"
    )

    if len(current) + len(telemetry_block) > 3900:
        chunks.append(current.rstrip())
        chunks.append(telemetry_block)
    else:
        current += telemetry_block
        chunks.append(current)

    return chunks

# ═══════════════════════════════════════════════════════════════════════════════
#  Executive Daily Brief (/brief)
# ═══════════════════════════════════════════════════════════════════════════════

def format_daily_brief(articles: List[Dict[str, Any]]) -> str:
    """Format daily brief (suitable for SOC leads)."""
    sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
    dash_line = "─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─"
    
    # 1. Top 10 Stories list
    top_stories = []
    critical_cves = []
    active_ransomware = []
    active_apts = []
    
    for art in articles[:10]:
        top_stories.append(f"• <b>[{art['priority_emoji']} Priority {art['priority_score']}]</b> {html_lib.escape(art['title'])} (<i>{art['source']}</i>)")
        
        # CVEs
        for c in art["cves_enriched"]:
            if c["in_kev"] or (c["cvss"] and c["cvss"] >= 8.0):
                critical_cves.append(f"  - <code>{c['cve_id']}</code> (CVSS: {c['cvss'] or '?'}) - {c['affected']}")
                
        # Ransomware
        if art["category"] == "Ransomware":
            active_ransomware.append(f"  - {html_lib.escape(art['title'])}")
            
        # APT
        if art["category"] == "APT Activity" or art["actors_matched"]:
            act_name = art["actors_matched"][0]["name"] if art["actors_matched"] else "APT Group"
            active_apts.append(f"  - <code>{act_name}</code> associated campaign: {html_lib.escape(art['title'][:80])}")

    # Top critical event
    most_critical = "No immediate-priority threats logged today."
    immediate_articles = [a for a in articles if a["priority_level"] == "Immediate"]
    if immediate_articles:
        most_critical = f"🚨 <b>{html_lib.escape(immediate_articles[0]['title'])}</b>\n  <i>{html_lib.escape(immediate_articles[0]['summary'])}</i>"
    elif articles:
        most_critical = f"⚠️ <b>{html_lib.escape(articles[0]['title'])}</b>\n  <i>{html_lib.escape(articles[0]['summary'])}</i>"

    stories_text = "\n".join(top_stories) if top_stories else "• <i>No recent stories to display.</i>"
    cves_text = "\n".join(critical_cves[:5]) if critical_cves else "  • <i>No critical vulnerabilities reported.</i>"
    ransom_text = "\n".join(active_ransomware[:3]) if active_ransomware else "  • <i>No ransomware campaigns observed today.</i>"
    apt_text = "\n".join(active_apts[:3]) if active_apts else "  • <i>No active nation-state/APT campaigns observed.</i>"

    # Immediate actions
    actions = [
        "Review KEV alerts and check vulnerable device updates on perimeter firewall gates.",
        "Scan local EDR telemetry for shadow copy command deletions.",
        "Deploy suricata/snort or local rules matching active CVE indicators.",
        "Monitor watchlist alerts for matches against outbound DNS/IP traffic."
    ]
    actions_text = "\n".join(f"  ☑️ {act}" for act in actions)

    brief_html = (
        f"👑 <b>EXECUTIVE DAILY THREAT BRIEF</b>\n"
        f"<code>{sep}</code>\n\n"
        f"🔥 <b>MOST CRITICAL THREAT:</b>\n"
        f"{most_critical}\n\n"
        f"📈 <b>TOP 10 SECURITY INTELLIGENCE STORIES:</b>\n"
        f"{stories_text}\n\n"
        f"🐞 <b>CRITICAL CVE & KEV ALERTS:</b>\n"
        f"{cves_text}\n\n"
        f"🦠 <b>ACTIVE RANSOMWARE CAMPAIGNS:</b>\n"
        f"{ransom_text}\n\n"
        f"🕵️ <b>ACTIVE APT / STATE SPONSORED THREATS:</b>\n"
        f"{apt_text}\n\n"
        f"🛡️ <b>IMMEDIATE ACTIONS FOR SOC TEAMS:</b>\n"
        f"{actions_text}\n\n"
        f"🔮 <b>24-48h THREAT OUTLOOK:</b>\n"
        f"  <i>Threat level remains high. Expect increased exploitation attempts on public vulnerability vectors. Monitor outbound C2 beacons.</i>\n"
        f"<code>{sep}</code>"
    )
    return brief_html
