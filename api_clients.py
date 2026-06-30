"""
api_clients.py - Async API clients for all threat intelligence sources.

Supported sources:
  - VirusTotal v3
  - AbuseIPDB v2
  - AlienVault OTX v1
  - ip-api.com (GeoIP + ASN)
  - Google DNS-over-HTTPS (DNS resolution)
  - WHOIS via whois.iana.org / rdap
"""
import asyncio
import urllib.parse
from typing import Optional
import httpx
import config

# ─── HTTP client factory ──────────────────────────────────────────────────────

def _client(timeout: int = 20) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=timeout, follow_redirects=True)


# ═══════════════════════════════════════════════════════════════════════════════
#  VirusTotal
# ═══════════════════════════════════════════════════════════════════════════════

_VT_BASE = "https://www.virustotal.com/api/v3"

async def vt_check_ip(ip: str) -> dict:
    if not config.HAS_VT:
        return {"error": "VirusTotal API key not configured"}
    async with _client() as c:
        r = await c.get(
            f"{_VT_BASE}/ip_addresses/{ip}",
            headers={"x-apikey": config.VT_API_KEY},
        )
    if r.status_code != 200:
        return {"error": f"VT HTTP {r.status_code}"}
    data = r.json().get("data", {}).get("attributes", {})
    stats = data.get("last_analysis_stats", {})
    return {
        "malicious":              stats.get("malicious", 0),
        "suspicious":             stats.get("suspicious", 0),
        "harmless":               stats.get("harmless", 0),
        "undetected":             stats.get("undetected", 0),
        "reputation":             data.get("reputation", 0),
        "country":                data.get("country", ""),
        "asn":                    data.get("asn", ""),
        "as_owner":               data.get("as_owner", ""),
        "network":                data.get("network", ""),
        "last_analysis_results": data.get("last_analysis_results", {}),
    }


async def vt_get_passive_dns(ip: str) -> dict:
    if not config.HAS_VT:
        return {"error": "VirusTotal API key not configured"}
    try:
        async with _client() as c:
            r = await c.get(
                f"{_VT_BASE}/ip_addresses/{ip}/resolutions?limit=40",
                headers={"x-apikey": config.VT_API_KEY},
            )
        if r.status_code != 200:
            return {"error": f"VT HTTP {r.status_code}"}
        
        res_data = r.json().get("data", [])
        records = []
        import datetime
        for item in res_data:
            attrs = item.get("attributes", {})
            date_epoch = attrs.get("date", 0)
            try:
                date_str = datetime.datetime.fromtimestamp(date_epoch, tz=datetime.timezone.utc).strftime("%Y-%m-%d")
            except Exception:
                date_str = "0000-00-00"
            
            domain = attrs.get("host_name", "")
            stats = attrs.get("host_name_last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 0
            detection = f"{mal}/{total}" if total else ""
            
            if domain:
                records.append({
                    "date": date_str,
                    "domain": domain,
                    "detection": detection,
                    "epoch": date_epoch
                })
        
        records.sort(key=lambda x: x["epoch"], reverse=True)
        return {"records": records}
    except Exception as e:
        return {"error": str(e)}


async def vt_check_domain(domain: str) -> dict:
    if not config.HAS_VT:
        return {"error": "VirusTotal API key not configured"}
    async with _client() as c:
        r = await c.get(
            f"{_VT_BASE}/domains/{domain}",
            headers={"x-apikey": config.VT_API_KEY},
        )
    if r.status_code != 200:
        return {"error": f"VT HTTP {r.status_code}"}
    data = r.json().get("data", {}).get("attributes", {})
    stats = data.get("last_analysis_stats", {})
    return {
        "malicious":              stats.get("malicious", 0),
        "suspicious":             stats.get("suspicious", 0),
        "harmless":               stats.get("harmless", 0),
        "undetected":             stats.get("undetected", 0),
        "reputation":             data.get("reputation", 0),
        "registrar":              data.get("registrar", ""),
        "creation_date":          data.get("creation_date", ""),
        "categories":             data.get("categories", {}),
        "last_analysis_results": data.get("last_analysis_results", {}),
    }


async def vt_check_url(url: str) -> dict:
    if not config.HAS_VT:
        return {"error": "VirusTotal API key not configured"}
    # VT URL lookup requires URL-safe base64 encoded URL id
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    async with _client() as c:
        r = await c.get(
            f"{_VT_BASE}/urls/{url_id}",
            headers={"x-apikey": config.VT_API_KEY},
        )
    if r.status_code == 404:
        # Submit for analysis first
        async with _client() as c2:
            r2 = await c2.post(
                f"{_VT_BASE}/urls",
                headers={"x-apikey": config.VT_API_KEY},
                data={"url": url},
            )
        return {"error": "URL submitted for analysis. Try again in ~1 min.", "submitted": True}
    if r.status_code != 200:
        return {"error": f"VT HTTP {r.status_code}"}
    data = r.json().get("data", {}).get("attributes", {})
    stats = data.get("last_analysis_stats", {})
    return {
        "malicious":              stats.get("malicious", 0),
        "suspicious":             stats.get("suspicious", 0),
        "harmless":               stats.get("harmless", 0),
        "undetected":             stats.get("undetected", 0),
        "reputation":             data.get("reputation", 0),
        "final_url":              data.get("last_final_url", url),
        "title":                  data.get("title", ""),
        "last_analysis_results": data.get("last_analysis_results", {}),
    }


async def vt_check_hash(file_hash: str) -> dict:
    if not config.HAS_VT:
        return {"error": "VirusTotal API key not configured"}
    async with _client() as c:
        r = await c.get(
            f"{_VT_BASE}/files/{file_hash}",
            headers={"x-apikey": config.VT_API_KEY},
        )
    if r.status_code == 404:
        return {"error": "Hash not found in VirusTotal database"}
    if r.status_code != 200:
        return {"error": f"VT HTTP {r.status_code}"}
    data = r.json().get("data", {}).get("attributes", {}) or {}
    stats = data.get("last_analysis_stats", {}) or {}
    
    names = data.get("names")
    file_name = ""
    if isinstance(names, list) and names:
        file_name = names[0] or ""
    elif isinstance(names, str):
        file_name = names
        
    pop_class = data.get("popular_threat_classification")
    threat_label = ""
    if isinstance(pop_class, dict):
        threat_label = pop_class.get("suggested_threat_label", "") or ""
        
    return {
        "malicious":              stats.get("malicious", 0) or 0,
        "suspicious":             stats.get("suspicious", 0) or 0,
        "harmless":               stats.get("harmless", 0) or 0,
        "undetected":             stats.get("undetected", 0) or 0,
        "type_desc":              data.get("type_description", "") or "",
        "file_name":              file_name,
        "file_size":              data.get("size", 0) or 0,
        "md5":                    data.get("md5", "") or "",
        "sha1":                   data.get("sha1", "") or "",
        "sha256":                 data.get("sha256", "") or "",
        "magic":                  data.get("magic", "") or "",
        "threat_label":           threat_label,
        "last_analysis_results": data.get("last_analysis_results", {}),
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  AbuseIPDB
# ═══════════════════════════════════════════════════════════════════════════════

async def abuseipdb_check(ip: str) -> dict:
    if not config.HAS_ABUSEIPDB:
        return {"error": "AbuseIPDB API key not configured"}
    async with _client() as c:
        r = await c.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": False},
        )
    if r.status_code != 200:
        return {"error": f"AbuseIPDB HTTP {r.status_code}"}
    d = r.json().get("data", {})
    return {
        "abuse_score":   d.get("abuseConfidenceScore", 0),
        "total_reports": d.get("totalReports", 0),
        "country_code":  d.get("countryCode", ""),
        "usage_type":    d.get("usageType", ""),
        "isp":           d.get("isp", ""),
        "domain":        d.get("domain", ""),
        "is_public":     d.get("isPublic", True),
        "is_tor":        d.get("isTor", False),
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  AlienVault OTX
# ═══════════════════════════════════════════════════════════════════════════════

_OTX_BASE = "https://otx.alienvault.com/api/v1"

async def _otx_get(path: str) -> dict:
    headers = {}
    if config.HAS_OTX:
        headers["X-OTX-API-KEY"] = config.OTX_API_KEY
    try:
        async with _client(timeout=15) as c:
            r = await c.get(f"{_OTX_BASE}{path}", headers=headers)
    except Exception as e:
        err = str(e) or type(e).__name__
        return {"error": f"OTX timeout/error: {err[:60]}"}
    if r.status_code != 200:
        return {"error": f"OTX HTTP {r.status_code}"}
    return r.json()


async def otx_check_ip(ip: str) -> dict:
    data = await _otx_get(f"/indicators/IPv4/{ip}/general")
    if "error" in data:
        return data
    pulses = data.get("pulse_info", {})
    return {
        "pulse_count":  pulses.get("count", 0),
        "pulses":       pulses.get("pulses", [])[:5],
        "reputation":   data.get("reputation", 0),
        "country_name": data.get("country_name", ""),
        "city":         data.get("city", ""),
        "asn":          data.get("asn", ""),
    }


async def otx_check_domain(domain: str) -> dict:
    data = await _otx_get(f"/indicators/domain/{domain}/general")
    if "error" in data:
        return data
    pulses = data.get("pulse_info", {})
    return {
        "pulse_count":  pulses.get("count", 0),
        "pulses":       pulses.get("pulses", [])[:5],
        "alexa":        data.get("alexa", ""),
        "whois":        data.get("whois", ""),
    }


async def otx_check_hash(file_hash: str) -> dict:
    data = await _otx_get(f"/indicators/file/{file_hash}/general")
    if "error" in data:
        return data
    pulses = data.get("pulse_info", {}) or {}
    analysis = data.get("analysis", {}) or {}
    
    pulse_list = pulses.get("pulses")
    if not isinstance(pulse_list, list):
        pulse_list = []
        
    malware_family = ""
    if isinstance(analysis, dict):
        info = analysis.get("info")
        if isinstance(info, dict):
            results = info.get("results")
            if isinstance(results, dict):
                malware_family = results.get("malware_family", "") or ""
                
    return {
        "pulse_count":   pulses.get("count", 0) or 0,
        "pulses":        pulse_list[:5],
        "malware_family": malware_family,
    }


async def otx_check_url(url: str) -> dict:
    encoded = urllib.parse.quote(url, safe="")
    data = await _otx_get(f"/indicators/url/{encoded}/general")
    if "error" in data:
        return data
    pulses = data.get("pulse_info", {})
    return {
        "pulse_count": pulses.get("count", 0),
        "pulses":      pulses.get("pulses", [])[:5],
    }


async def otx_get_recent_pulses(limit: int = 5) -> list:
    """Fetch recent public OTX pulses for feed monitoring."""
    data = await _otx_get(f"/pulses/activity?limit={limit}")
    if "error" in data or "results" not in data:
        return []
    return data["results"]


# ═══════════════════════════════════════════════════════════════════════════════
#  GeoIP + ASN  (ip-api.com — free, no key needed)
# ═══════════════════════════════════════════════════════════════════════════════

async def geoip_lookup(ip: str) -> dict:
    fields = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
    async with _client() as c:
        r = await c.get(f"http://ip-api.com/json/{ip}?fields={fields}")
    if r.status_code != 200:
        return {"error": f"ip-api HTTP {r.status_code}"}
    d = r.json()
    if d.get("status") == "fail":
        return {"error": d.get("message", "Unknown error")}
    return {
        "country":      d.get("country", ""),
        "country_code": d.get("countryCode", ""),
        "city":         d.get("city", ""),
        "region":       d.get("regionName", ""),
        "isp":          d.get("isp", ""),
        "org":          d.get("org", ""),
        "asn":          d.get("as", ""),
        "timezone":     d.get("timezone", ""),
        "lat":          d.get("lat"),
        "lon":          d.get("lon"),
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  DNS Resolution (Google DoH)
# ═══════════════════════════════════════════════════════════════════════════════

_DNS_TYPE_MAP = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 2: "NS"}

async def dns_resolve(name: str, record_type: str = "A") -> dict:
    type_map = {"A": 1, "AAAA": 28, "MX": 15, "TXT": 16, "NS": 2, "CNAME": 5}
    qtype = type_map.get(record_type.upper(), 1)
    async with _client() as c:
        r = await c.get(
            "https://dns.google/resolve",
            params={"name": name, "type": qtype},
            headers={"Accept": "application/dns-json"},
        )
    if r.status_code != 200:
        return {"error": f"DNS HTTP {r.status_code}"}
    data = r.json()
    answers = []
    for rec in data.get("Answer", []):
        answers.append({
            "type": _DNS_TYPE_MAP.get(rec.get("type", 0), str(rec.get("type"))),
            "data": rec.get("data", ""),
            "ttl":  rec.get("TTL", 0),
        })
    return {
        "status":  data.get("Status", -1),
        "answers": answers,
        "nx":      data.get("Status", -1) == 3,
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  RDAP / WHOIS (via IANA RDAP bootstrap)
# ═══════════════════════════════════════════════════════════════════════════════

async def rdap_domain(domain: str) -> dict:
    tld = domain.rsplit(".", 1)[-1].lower()
    rdap_url = f"https://rdap.org/domain/{domain}"
    async with _client(timeout=15) as c:
        try:
            r = await c.get(rdap_url)
        except Exception as e:
            return {"error": str(e)}
    if r.status_code != 200:
        return {"error": f"RDAP HTTP {r.status_code}"}
    d = r.json()
    # Extract registrar
    registrar = ""
    for entity in d.get("entities", []):
        roles = entity.get("roles", [])
        if "registrar" in roles:
            vcard = entity.get("vcardArray", [None, []])[1]
            for field in vcard:
                if field[0] == "fn":
                    registrar = field[3]
    # Extract dates
    events = {e["eventAction"]: e["eventDate"] for e in d.get("events", [])}
    return {
        "registrar":    registrar,
        "registered":   events.get("registration", ""),
        "expiration":   events.get("expiration", ""),
        "last_changed": events.get("last changed", ""),
        "status":       d.get("status", []),
        "nameservers":  [ns.get("ldhName", "") for ns in d.get("nameservers", [])],
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  Threat Feed: CISA KEV
# ═══════════════════════════════════════════════════════════════════════════════

async def fetch_cisa_kev() -> list:
    """Return list of newly added KEV entries (returns all, caller filters)."""
    async with _client(timeout=30) as c:
        try:
            r = await c.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            )
        except Exception:
            return []
    if r.status_code != 200:
        return []
    data = r.json()
    return data.get("vulnerabilities", [])


# ═══════════════════════════════════════════════════════════════════════════════
#  Threat Feed: URLhaus (abuse.ch)
# ═══════════════════════════════════════════════════════════════════════════════

async def fetch_urlhaus_recent() -> list:
    """Return recent malware URLs from URLhaus."""
    async with _client(timeout=30) as c:
        try:
            r = await c.post(
                "https://urlhaus-api.abuse.ch/v1/urls/recent/",
                data={"limit": 10},
            )
        except Exception:
            return []
    if r.status_code != 200:
        return []
    return r.json().get("urls", [])


# ═══════════════════════════════════════════════════════════════════════════════
#  Shodan Lookup
# ═══════════════════════════════════════════════════════════════════════════════

async def shodan_check_ip(ip: str) -> dict:
    if not config.SHODAN_API_KEY:
        return {"error": "Shodan API key not configured"}
    async with _client() as c:
        try:
            r = await c.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": config.SHODAN_API_KEY}
            )
            if r.status_code == 200:
                data = r.json()
                return {
                    "ports": data.get("ports", []),
                    "isp": data.get("isp", ""),
                    "os": data.get("os", ""),
                    "vulns": data.get("vulns", []),
                    "hostnames": data.get("hostnames", []),
                    "country_name": data.get("country_name", ""),
                }
            elif r.status_code == 404:
                return {"error": "No information found for this IP"}
            else:
                return {"error": f"Shodan HTTP {r.status_code}"}
        except Exception as e:
            return {"error": f"Shodan error: {str(e)}"}


# ═══════════════════════════════════════════════════════════════════════════════
#  GreyNoise Lookup
# ═══════════════════════════════════════════════════════════════════════════════

async def greynoise_check_ip(ip: str) -> dict:
    if not config.GREYNOISE_API_KEY:
        return {"error": "GreyNoise API key not configured"}
    headers = {"key": config.GREYNOISE_API_KEY}
    async with _client() as c:
        try:
            r = await c.get(
                f"https://api.greynoise.io/v3/community/{ip}",
                headers=headers
            )
            if r.status_code == 200:
                data = r.json()
                return {
                    "noise": data.get("noise", False),
                    "riot": data.get("riot", False),
                    "classification": data.get("classification", "unknown"),
                    "name": data.get("name", "unknown"),
                    "last_seen": data.get("last_seen", ""),
                    "message": data.get("message", ""),
                }
            else:
                return {"error": f"GreyNoise HTTP {r.status_code}"}
        except Exception as e:
            return {"error": f"GreyNoise error: {str(e)}"}


async def rdap_ip(ip: str) -> dict:
    """Fetch WHOIS/RDAP registration records for an IP address."""
    rdap_url = f"https://rdap.org/ip/{ip}"
    async with _client(timeout=15) as c:
        try:
            r = await c.get(rdap_url)
            if r.status_code == 200:
                return r.json()
            else:
                return {"error": f"RDAP IP HTTP {r.status_code}"}
        except Exception as e:
            return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
#  DNS Multi-Record Resolver
# ═══════════════════════════════════════════════════════════════════════════════

async def dns_resolve_all(name: str) -> dict:
    """
    Concurrently resolve A, AAAA, MX, NS, TXT, and CNAME records.
    Returns a dict: {"A": [...], "AAAA": [...], "MX": [...], ...}
    Each list contains dicts with 'type', 'data', 'ttl'.
    """
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    results_raw = await asyncio.gather(
        *[dns_resolve(name, rt) for rt in record_types],
        return_exceptions=True,
    )
    dns_map: dict = {}
    for rt, res in zip(record_types, results_raw):
        if isinstance(res, Exception) or not isinstance(res, dict) or res.get("error"):
            continue
        answers = res.get("answers", [])
        if answers:
            dns_map[rt] = answers
    return dns_map


# ═══════════════════════════════════════════════════════════════════════════════
#  VirusTotal Community Comments
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_vt_comments(raw: dict) -> list:
    """
    Parse VT /comments API response into a list of dicts:
    [{"date": "YYYY-MM-DD", "author": str, "text": str}, ...]
    sorted newest first.
    """
    items = []
    for entry in (raw.get("data") or []):
        attrs = entry.get("attributes") or {}
        raw_date = attrs.get("date") or ""
        # VT returns Unix timestamp as int
        if isinstance(raw_date, int):
            from datetime import datetime, timezone
            date_str = datetime.fromtimestamp(raw_date, tz=timezone.utc).strftime("%Y-%m-%d")
        else:
            date_str = str(raw_date)[:10]
        text = str(attrs.get("text") or "").strip()
        author = str(attrs.get("author") or {}).strip()
        if isinstance(attrs.get("author"), dict):
            author = attrs["author"].get("name", "anonymous")
        if text:
            items.append({"date": date_str, "author": author, "text": text})
    items.sort(key=lambda x: x["date"], reverse=True)
    return items


async def vt_comments_ip(ip: str, limit: int = 10) -> list:
    """Fetch community comments for an IP from VirusTotal."""
    if not config.HAS_VT:
        return []
    try:
        async with _client() as c:
            r = await c.get(
                f"{_VT_BASE}/ip_addresses/{ip}/comments",
                headers={"x-apikey": config.VT_API_KEY},
                params={"limit": limit},
            )
        if r.status_code == 200:
            return _parse_vt_comments(r.json())
    except Exception:
        pass
    return []


async def vt_comments_domain(domain: str, limit: int = 10) -> list:
    """Fetch community comments for a domain from VirusTotal."""
    if not config.HAS_VT:
        return []
    try:
        async with _client() as c:
            r = await c.get(
                f"{_VT_BASE}/domains/{domain}/comments",
                headers={"x-apikey": config.VT_API_KEY},
                params={"limit": limit},
            )
        if r.status_code == 200:
            return _parse_vt_comments(r.json())
    except Exception:
        pass
    return []


async def vt_comments_hash(file_hash: str, limit: int = 10) -> list:
    """Fetch community comments for a file hash from VirusTotal."""
    if not config.HAS_VT:
        return []
    try:
        async with _client() as c:
            r = await c.get(
                f"{_VT_BASE}/files/{file_hash}/comments",
                headers={"x-apikey": config.VT_API_KEY},
                params={"limit": limit},
            )
        if r.status_code == 200:
            return _parse_vt_comments(r.json())
    except Exception:
        pass
    return []


async def vt_comments_url(url: str, limit: int = 10) -> list:
    """Fetch community comments for a URL from VirusTotal."""
    if not config.HAS_VT:
        return []
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        async with _client() as c:
            r = await c.get(
                f"{_VT_BASE}/urls/{url_id}/comments",
                headers={"x-apikey": config.VT_API_KEY},
                params={"limit": limit},
            )
        if r.status_code == 200:
            return _parse_vt_comments(r.json())
    except Exception:
        pass
    return []

