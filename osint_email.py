"""
osint_email.py - Core Engine for Email OSINT, Breach Intelligence, & Identity Correlation.
Ties together DNS, WHOIS, Breach, Threat Intel, and Username OSINT engines.
"""
import asyncio
import logging
import re
import os
import httpx
import dns.resolver
import smtplib
import socket
from datetime import datetime
import api_clients as api
import osint_username

logger = logging.getLogger(__name__)

# List of common disposable email domains
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "guerrillamailblock.com", "guerrillamail.net", 
    "guerrillamail.org", "guerrillamail.biz", "tempmail.com", "10minutemail.com", 
    "throwawaymail.com", "yopmail.com", "maildrop.cc", "sharklasers.com", 
    "dispostable.com", "getairmail.com", "mailnesia.com", "mailcatch.com", 
    "temp-mail.org", "fakemailgenerator.com", "burnermail.io", "trashmail.com",
    "moakt.com", "pokemail.net", "dropmail.me", "safe-mail.net", "minuteinbox.com"
}

# List of popular public email providers
PUBLIC_PROVIDERS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", 
    "yahoo.com", "ymail.com", "protonmail.com", "proton.me", "icloud.com", 
    "aol.com", "zoho.com", "zoho.in", "yandex.com", "yandex.ru", "mail.ru", 
    "gmx.com", "gmx.de", "tuta.com", "tutanota.com", "mail.com", "fastmail.com"
}

# ── DNS & Security Resolvers ──────────────────────────────────────────────────

def check_mx_records(domain: str) -> list[str]:
    """Retrieve MX records for the domain."""
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return [f"{r.exchange.to_text().rstrip('.')} (Priority: {r.preference})" for r in answers]
    except Exception:
        return []

def check_spf_dmarc(domain: str) -> tuple[str, str]:
    """Retrieve SPF and DMARC TXT records."""
    spf = "None"
    dmarc = "None"
    
    # SPF check
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            for txt in rdata.strings:
                txt_str = txt.decode('utf-8', errors='ignore') if isinstance(txt, bytes) else txt
                if "v=spf1" in txt_str:
                    spf = txt_str
                    break
    except Exception:
        pass
        
    # DMARC check
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for rdata in answers:
            for txt in rdata.strings:
                txt_str = txt.decode('utf-8', errors='ignore') if isinstance(txt, bytes) else txt
                if "v=DMARC1" in txt_str:
                    dmarc = txt_str
                    break
    except Exception:
        pass
        
    return spf, dmarc

def check_dkim_records(domain: str) -> list[str]:
    """Probes common DKIM selectors to find active records."""
    common_selectors = ["default", "google", "k1", "mail", "s1", "smtp"]
    found_dkim = []
    
    for selector in common_selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            answers = dns.resolver.resolve(dkim_domain, 'TXT')
            for rdata in answers:
                for txt in rdata.strings:
                    txt_str = txt.decode('utf-8', errors='ignore') if isinstance(txt, bytes) else txt
                    if "v=DKIM1" in txt_str or "p=" in txt_str:
                        found_dkim.append(f"{selector}: {txt_str[:60]}...")
        except Exception:
            pass
            
    return found_dkim

def check_dns_records(domain: str) -> dict[str, list[str]]:
    """Retrieve other general DNS records (A, AAAA, NS, TXT, CNAME)."""
    dns_info = {}
    for rtype in ["A", "AAAA", "NS", "CNAME", "TXT"]:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            dns_info[rtype] = [str(r) for r in answers]
        except Exception:
            dns_info[rtype] = []
    return dns_info

# ── Domain Metadata / WHOIS ───────────────────────────────────────────────────

async def get_domain_metadata(domain: str) -> dict:
    """Gets Registrar and Creation dates, calculates Domain Age."""
    rdap = await api.rdap_domain(domain)
    if "error" in rdap:
        return {
            "registrar": "Unknown",
            "created_date": "Unknown",
            "age": "Unknown",
            "error": rdap["error"]
        }
        
    created = rdap.get("registered", "")
    age_str = "Unknown"
    
    if created:
        try:
            # Parse created date (handles ISO like '1992-06-18' or '1992-06-18T00:00:00Z')
            clean_date = created.split("T")[0]
            dt = datetime.strptime(clean_date, "%Y-%m-%d")
            delta = datetime.now() - dt
            years = delta.days // 365
            months = (delta.days % 365) // 30
            if years > 0:
                age_str = f"{years} years, {months} months"
            else:
                age_str = f"{months} months"
        except Exception:
            pass
            
    return {
        "registrar": rdap.get("registrar", "Unknown") or "Unknown",
        "created_date": created or "Unknown",
        "age": age_str
    }

# ── SMTP Catch-All Checking ───────────────────────────────────────────────────

def smtp_catch_all_check(domain: str, mx_server: str) -> str:
    """Connects to port 25 to check if SMTP accepts random emails (Catch-All)."""
    if not mx_server:
        return "NO (No MX configured)"
        
    hostname = mx_server.split()[0] if " " in mx_server else mx_server
    try:
        with smtplib.SMTP(hostname, port=25, timeout=3.0) as smtp:
            smtp.helo("osint-bot.local")
            smtp.mail("osint-check@gmail.com")
            
            # Recipient verification on random address
            code, msg = smtp.rcpt(f"random_osint_verify_{socket.gethostname()[:5]}@local.com")
            
            if code == 250:
                return "YES"
            elif code in (550, 551, 553):
                return "NO"
            else:
                return f"UNKNOWN (SMTP Code {code})"
    except Exception as e:
        logger.debug(f"Catch-all connection error for {domain}: {e}")
        return "UNKNOWN (Connection blocked/timed out)"

# ── Breach Intelligence ────────────────────────────────────────────────────────

async def check_hibp_breaches(email: str) -> dict:
    """Checks HaveIBeenPwned if API key is configured."""
    api_key = os.getenv("HIBP_API_KEY", "")
    if not api_key:
        return {"checked": False, "status": "Key Missing", "breaches": []}
        
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {"hibp-api-key": api_key, "user-agent": "Antigravity-Threat-Bot/2.0"}
    
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(url, headers=headers)
            if r.status_code == 200:
                return {"checked": True, "status": "Leaked", "breaches": r.json()[:10]}
            elif r.status_code == 404:
                return {"checked": True, "status": "Secure", "breaches": []}
            else:
                return {"checked": False, "status": f"HTTP {r.status_code}", "breaches": []}
    except Exception as e:
        return {"checked": False, "status": f"Error: {str(e)[:30]}", "breaches": []}

async def check_leakcheck(email: str) -> dict:
    """Checks LeakCheck API (falls back to Public API if no key)."""
    api_key = os.getenv("LEAKCHECK_API_KEY", "")
    
    if api_key:
        # Use Pro/v2 API
        url = f"https://leakcheck.io/api/v2/query/{email}"
        headers = {"X-API-Key": api_key}
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                r = await client.get(url, headers=headers)
                if r.status_code == 200:
                    data = r.json()
                    if data.get("success"):
                        breaches = []
                        for res in data.get("result", []):
                            src = res.get("source", {})
                            breaches.append({
                                "Name": src.get("name", "Unknown"),
                                "Date": src.get("breach_date", "Unknown")
                            })
                        return {"checked": True, "status": "Leaked", "breaches": breaches}
                return {"checked": False, "status": f"HTTP {r.status_code}", "breaches": []}
        except Exception as e:
            return {"checked": False, "status": f"Error: {str(e)[:30]}", "breaches": []}
    else:
        # Use Free Public API (doesn't expose passwords, only breach names/dates)
        url = f"https://leakcheck.io/api/public?check={email}&type=email"
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                r = await client.get(url)
                if r.status_code == 200:
                    data = r.json()
                    if data.get("success"):
                        breaches = []
                        for src in data.get("sources", []):
                            breaches.append({
                                "Name": src.get("name", "Unknown"),
                                "Date": src.get("date", "Unknown")
                            })
                        status = "Leaked" if breaches else "Secure"
                        return {"checked": True, "status": status, "breaches": breaches}
                return {"checked": False, "status": f"HTTP {r.status_code}", "breaches": []}
        except Exception as e:
            return {"checked": False, "status": f"Error: {str(e)[:30]}", "breaches": []}

# ── Threat Intelligence ────────────────────────────────────────────────────────

async def query_threatfox(domain: str) -> dict:
    url = "https://threatfox-api.abuse.ch/v1/"
    payload = {"query": "search_ioc", "search_term": domain}
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.post(url, json=payload)
            if r.status_code == 200:
                data = r.json()
                if data.get("query_status") == "ok":
                    return {"found": True, "count": len(data.get("data", [])), "details": data.get("data", [])}
    except Exception:
        pass
    return {"found": False, "count": 0}

async def query_urlhaus(domain: str) -> dict:
    url = "https://urlhaus-api.abuse.ch/v1/host/"
    payload = {"host": domain}
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.post(url, data=payload)
            if r.status_code == 200:
                data = r.json()
                if data.get("query_status") == "ok":
                    return {"found": True, "count": data.get("url_count", 0)}
    except Exception:
        pass
    return {"found": False, "count": 0}

async def query_urlscan(domain: str) -> dict:
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(url)
            if r.status_code == 200:
                data = r.json()
                total = data.get("total", 0)
                return {"found": total > 0, "count": total}
    except Exception:
        pass
    return {"found": False, "count": 0}

async def get_domain_threat_reputation(domain: str) -> dict:
    """Enriches domain reputation querying VT, OTX, ThreatFox, URLHaus, URLScan, and AbuseIPDB."""
    # VT and OTX
    vt_res = await api.vt_check_domain(domain)
    otx_res = await api.otx_check_domain(domain)
    
    # Free/API-keyless checks
    tf_res = await query_threatfox(domain)
    uh_res = await query_urlhaus(domain)
    us_res = await query_urlscan(domain)
    
    # AbuseIPDB on resolved A record IP
    abuse_score = 0
    resolved_ips = []
    try:
        answers = dns.resolver.resolve(domain, 'A')
        resolved_ips = [str(r) for r in answers]
    except Exception:
        pass
        
    if resolved_ips:
        abuse_ip_res = await api.abuseipdb_check(resolved_ips[0])
        if "error" not in abuse_ip_res:
            abuse_score = abuse_ip_res.get("abuse_score", 0)
            
    # Compile stats
    vt_mal = vt_res.get("malicious", 0) if "error" not in vt_res else 0
    otx_pulses = otx_res.get("pulse_count", 0) if "error" not in otx_res else 0
    tf_detections = tf_res["count"]
    uh_detections = uh_res["count"]
    us_detections = us_res["count"]
    
    # Scoring & Reputation verdict
    reputation_score = vt_mal + otx_pulses + tf_detections + uh_detections + (1 if abuse_score > 10 else 0)
    
    if reputation_score >= 5:
        verdict = "MALICIOUS"
    elif reputation_score >= 1:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"
        
    return {
        "verdict": verdict,
        "score": reputation_score,
        "vt_malicious": vt_mal,
        "otx_pulses": otx_pulses,
        "threatfox_detections": tf_detections,
        "urlhaus_detections": uh_detections,
        "urlscan_detections": us_detections,
        "abuseipdb_score": abuse_score,
        "ips": resolved_ips
    }

# ── Username Generation & Correlation ──────────────────────────────────────────

def generate_usernames(local_part: str) -> list[str]:
    """Generates a limited number of high-confidence usernames (max 4, len >= 3)."""
    handles = []
    orig = local_part.lower()
    
    # Rule 1: Original local part
    if len(orig) >= 3:
        handles.append(orig)
        
    # Rule 2: Remove special separators
    stripped = re.sub(r'[\.\-_\+]', '', orig)
    if len(stripped) >= 3 and stripped not in handles:
        handles.append(stripped)
        
    # Rule 3: Normalize to underscore
    replaced = re.sub(r'[\.\-\+]', '_', orig)
    if len(replaced) >= 3 and replaced not in handles:
        handles.append(replaced)
        
    # Rule 4: Extract segments
    parts = re.split(r'[\.\-_\+]', orig)
    for part in parts:
        if len(part) >= 3 and part not in handles:
            handles.append(part)
            
    # Limit to maximum of 4 usernames
    return handles[:4]

async def correlate_username_profiles(usernames: list[str]) -> list[dict]:
    """Concurrently queries Username OSINT Discovery engine for all generated usernames."""
    tasks = [osint_username.run_username_scan(u) for u in usernames]
    scans = await asyncio.gather(*tasks)
    
    all_discovered = []
    for username, scan_results in zip(usernames, scans):
        found = [r for r in scan_results if r["status"] == "Found"]
        if found:
            all_discovered.append({
                "username": username,
                "profiles": found
            })
    return all_discovered

# ── Exposure Score Calculator (0 - 100) ───────────────────────────────────────

def calculate_exposure_score(
    breaches_count: int,
    profiles_count: int,
    threat_verdict: str,
    missing_spf: bool,
    missing_dmarc: bool,
    missing_dkim: bool
) -> int:
    """Calculates overall Identity Exposure score from components."""
    # 1. Breaches (40 points max)
    if breaches_count == 0:
        breach_score = 0
    elif breaches_count <= 2:
        breach_score = 15
    elif breaches_count <= 5:
        breach_score = 30
    else:
        breach_score = 40
        
    # 2. Identity footprint (25 points max)
    if profiles_count == 0:
        profile_score = 0
    elif profiles_count <= 3:
        profile_score = 10
    elif profiles_count <= 8:
        profile_score = 20
    else:
        profile_score = 25
        
    # 3. Threat reputation (20 points max)
    if threat_verdict == "MALICIOUS":
        threat_score = 20
    elif threat_verdict == "SUSPICIOUS":
        threat_score = 10
    else:
        threat_score = 0
        
    # 4. Domain security (15 points max)
    security_score = 0
    if missing_spf:
        security_score += 5
    if missing_dmarc:
        security_score += 5
    if missing_dkim:
        security_score += 5
        
    return breach_score + profile_score + threat_score + security_score

# ── Core Runner ───────────────────────────────────────────────────────────────

async def run_email_investigation(email: str, progress_callback=None) -> dict:
    """Executes the complete Email OSINT and Identity Correlation pipeline."""
    # Phase 1: Email Parsing & Validation
    local_part, domain = email.split("@", 1)
    local_part = local_part.strip()
    domain = domain.strip().lower()
    
    # Progress: 10%
    if progress_callback: await progress_callback(10, "Validating DNS records & existence...")
    
    # Gather DNS & WHOIS
    spf_task = asyncio.to_thread(check_spf_dmarc, domain)
    mx_task = asyncio.to_thread(check_mx_records, domain)
    dkim_task = asyncio.to_thread(check_dkim_records, domain)
    dns_task = asyncio.to_thread(check_dns_records, domain)
    whois_task = get_domain_metadata(domain)
    
    (spf, dmarc), mx_records, dkim_records, dns_records, whois_res = await asyncio.gather(
        spf_task, mx_task, dkim_task, dns_task, whois_task
    )
    
    domain_exists = bool(dns_records.get("A") or dns_records.get("AAAA") or mx_records)
    
    # Progress: 30%
    if progress_callback: await progress_callback(30, "Analyzing email provider details...")
    
    # Provider Classification
    is_disposable = domain in DISPOSABLE_DOMAINS
    if domain in PUBLIC_PROVIDERS:
        provider_type = "Public Provider"
    elif is_disposable:
        provider_type = "Disposable Provider"
    else:
        provider_type = "Corporate / Custom Hosted"
        
    # SMTP Catch-All check
    primary_mx = mx_records[0] if mx_records else ""
    catch_all = await asyncio.to_thread(smtp_catch_all_check, domain, primary_mx)
    
    # Progress: 50%
    if progress_callback: await progress_callback(50, "Aggregating breach databases...")
    
    # Breaches
    hibp_task = check_hibp_breaches(email)
    lc_task = check_leakcheck(email)
    hibp_res, lc_res = await asyncio.gather(hibp_task, lc_task)
    
    # Merge breaches (dedup by name)
    breaches_map = {}
    
    # Process HIBP
    for b in hibp_res.get("breaches", []):
        name = b.get("Name", "Unknown")
        breaches_map[name.lower()] = {
            "name": name,
            "date": b.get("BreachDate", "Unknown")
        }
    # Process LeakCheck
    for b in lc_res.get("breaches", []):
        name = b.get("Name", "Unknown")
        breaches_map[name.lower()] = {
            "name": name,
            "date": b.get("Date", "Unknown")
        }
        
    all_breaches = list(breaches_map.values())
    
    # Exposure timeline
    dates = []
    for b in all_breaches:
        d_str = b["date"]
        if d_str and d_str != "Unknown":
            # Just extract year/month prefix
            dates.append(d_str.split("T")[0])
            
    earliest_exposure = min(dates) if dates else "Unknown"
    latest_exposure = max(dates) if dates else "Unknown"
    
    # Progress: 70%
    if progress_callback: await progress_callback(70, "Checking threat intelligence databases...")
    
    # Domain Threat Reputation
    threat_res = await get_domain_threat_reputation(domain)
    
    # Progress: 85%
    if progress_callback: await progress_callback(85, "Generating handles & scanning profiles...")
    
    # Username Generation & Correlation
    usernames = generate_usernames(local_part)
    correlated_profiles = await correlate_username_profiles(usernames)
    
    total_profiles_count = sum(len(c["profiles"]) for c in correlated_profiles)
    
    # Security Missing Flags
    missing_spf = (spf == "None")
    missing_dmarc = (dmarc == "None")
    missing_dkim = not bool(dkim_records) if provider_type != "Public Provider" else False
    
    # Progress: 100%
    if progress_callback: await progress_callback(100, "Compiling OSINT report...")
    
    # Exposure score
    exposure = calculate_exposure_score(
        len(all_breaches),
        total_profiles_count,
        threat_res["verdict"],
        missing_spf,
        missing_dmarc,
        missing_dkim
    )
    
    return {
        "email": email,
        "local_part": local_part,
        "domain": domain,
        "domain_exists": domain_exists,
        "provider_type": provider_type,
        "is_disposable": "YES" if is_disposable else "NO",
        "catch_all": catch_all,
        "dns_spf": spf,
        "dns_dmarc": dmarc,
        "dns_dkim": dkim_records,
        "mx_records": mx_records,
        "dns_records": dns_records,
        "whois": whois_res,
        "breach_count": len(all_breaches),
        "breaches": all_breaches,
        "earliest_exposure": earliest_exposure,
        "latest_exposure": latest_exposure,
        "threat_intel": threat_res,
        "generated_usernames": usernames,
        "discovered_profiles": correlated_profiles,
        "exposure_score": exposure
    }

def format_report_messages(res: dict) -> list[str]:
    """
    Compile the email investigation result into Telegram HTML messages.

    Layout (single report, split if > 4000 chars):
      Header
      \u2500\u2500 Email Validation
      \u2500\u2500 Domain Intelligence  (MX / SPF / DMARC / DKIM)
      \u2500\u2500 Breach Intelligence
      \u2500\u2500 Threat Intelligence
      \u2500\u2500 Identity Footprint
      \u2500\u2500 Raw Evidence Summary
      Footer
    """
    import html as _h

    SEP = "\u2501" * 26

    def _e(v):
        return _h.escape(str(v or ""))

    def _em_status(ok: bool) -> str:
        return "\u2705" if ok else "\u274c"

    # \u2500\u2500\u2500 Header \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    exp = res["exposure_score"]
    if exp >= 70:
        exp_em, exp_label = "\U0001f534", f"{exp}%  HIGH EXPOSURE"
    elif exp >= 35:
        exp_em, exp_label = "\U0001f7e1", f"{exp}%  MODERATE EXPOSURE"
    else:
        exp_em, exp_label = "\U0001f7e2", f"{exp}%  LOW EXPOSURE"

    ti        = res["threat_intel"]
    ti_verdict = str(ti.get("verdict") or "UNKNOWN")
    if ti_verdict == "MALICIOUS":
        ti_em = "\U0001f534"
    elif ti_verdict == "SUSPICIOUS":
        ti_em = "\U0001f7e1"
    else:
        ti_em = "\U0001f7e2"

    # Provider classification
    prov_raw = str(res.get("provider_type", "Unknown"))
    if "Disposable" in prov_raw:
        provider = "\U0001f5d1 Disposable"
    elif "Public" in prov_raw:
        provider = "\U0001f4e7 Public"
    else:
        provider = "\U0001f3e2 Corporate"

    header = (
        f"\U0001f4e7 <b>EMAIL INTELLIGENCE REPORT</b>\n"
        f"<code>{SEP}</code>\n"
        f"<b>Email</b>       <code>{_e(res['email'])}</code>\n"
        f"<b>Domain</b>      <code>{_e(res['domain'])}</code>\n"
        f"<code>{SEP}</code>\n\n"
    )

    domain_verdict = ti_verdict
    mx_ok = bool(res.get("mx_records"))
    status_str = "Valid" if mx_ok else "Invalid"
    
    v_upper = domain_verdict.upper()
    if v_upper in ("MALICIOUS", "CRITICAL", "HIGH", "HIGH RISK"):
        risk_em = "🔴"
        risk_lbl = "Malicious"
    elif v_upper in ("SUSPICIOUS", "MEDIUM", "LOW"):
        risk_em = "🟡"
        risk_lbl = "Suspicious"
    else:
        risk_em = "🟢"
        risk_lbl = "Clean"

    risk_summary = (
        f"<code>{SEP}</code>\n"
        f"📊 <b>EMAIL RISK SUMMARY</b>\n"
        f"<code>{SEP}</code>\n"
        f"<b>Status</b>             <code>{status_str}</code>\n"
        f"<b>Provider</b>           {provider}\n"
        f"<b>Domain Reputation</b>   {risk_em} <b>{risk_lbl}</b>\n\n"
    )

    # Email Validation
    is_disposable = "Disposable" in provider
    ca_raw = str(res.get("catch_all", "Unknown")).strip().upper()
    if ca_raw.startswith("NO"):
        catch_all_display = "No"
    elif ca_raw.startswith("YES"):
        catch_all_display = "Yes"
    else:
        catch_all_display = "Unknown"

    # SPF
    spf = str(res.get("dns_spf") or "None")
    if spf == "None" or not spf:
        spf_line = "\u274c Missing"
    elif "v=spf1" in spf:
        spf_line = f"\u2705 Active  <code>({_e(spf[:35])}...)</code>"
    else:
        spf_line = f"<code>({_e(spf[:35])}...)</code>"

    # DMARC
    dmarc = str(res.get("dns_dmarc") or "None")
    if dmarc == "None" or not dmarc:
        dmarc_line = "\u274c Missing"
    else:
        import re as _re
        pm = _re.search(r'p=(\w+)', dmarc)
        policy = pm.group(1).lower() if pm else "active"
        em_p = "\u2705" if policy in ("reject", "quarantine") else "⚠️"
        dmarc_line = f"{em_p} Policy: <code>{_e(policy)}</code>"

    # DKIM
    dkim_list = res.get("dns_dkim") or []
    if dkim_list:
        dkim_line = "\u2705 Active"
    else:
        dkim_line = "Not Detected"

    # MX listing
    mx_list = res.get("mx_records") or []
    if mx_list:
        mx_lines = "\n".join(f"  <code>{_e(mx[:70])}</code>" for mx in mx_list[:4])
        mx_block = f"<b>MX Records</b>\n{mx_lines}"
    else:
        mx_block = "<b>MX</b>               <code>Missing</code>"

    validation_block = (
        f"<code>{SEP}</code>\n"
        f"\u2709 <b>EMAIL VALIDATION</b>\n"
        f"<code>{SEP}</code>\n"
        f"{mx_block}\n"
        f"<b>SPF Record</b>     {spf_line}\n"
        f"<b>DMARC Policy</b>   {dmarc_line}\n"
        f"<b>DKIM</b>           {dkim_line}\n"
        f"<b>Catch-All</b>      <code>{catch_all_display}</code>\n"
        f"<b>Disposable</b>     {'⚠️ Yes' if is_disposable else '✅ No'}\n\n"
    )

    # \u2500\u2500\u2500 Domain Intelligence \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    # WHOIS
    meta = res.get("whois") or {}
    registrar   = str(meta.get("registrar") or "Unknown")
    created_raw = str(meta.get("created_date") or "Unknown")
    created     = created_raw.split("T")[0] if "T" in created_raw else created_raw
    age         = str(meta.get("age") or "Unknown")

    # A records
    dns_records = res.get("dns_records") or {}
    a_records   = dns_records.get("A") or []
    a_line = ", ".join(_e(a) for a in a_records[:4]) if a_records else "None"

    domain_block = (
        f"<code>{SEP}</code>\n"
        f"\U0001f310 <b>DOMAIN INTELLIGENCE</b>\n"
        f"<code>{SEP}</code>\n"
        f"<b>Registrar</b>      <code>{_e(registrar[:60])}</code>\n"
        f"<b>Registered</b>     <code>{_e(created)}</code>\n"
        f"<b>Domain Age</b>     <code>{_e(age)}</code>\n"
        f"<b>A Records</b>      <code>{a_line}</code>\n\n"
    )

    # \u2500\u2500\u2500 Breach Intelligence \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    breach_count = int(res.get("breach_count") or 0)
    if breach_count == 0:
        breach_block = (
            f"<code>{SEP}</code>\n"
            f"\U0001f525 <b>BREACH INTELLIGENCE</b>\n"
            f"<code>{SEP}</code>\n"
            f"🟢 No public breaches found\n\n"
        )
    else:
        breach_block = (
            f"<code>{SEP}</code>\n"
            f"\U0001f525 <b>BREACH INTELLIGENCE</b>\n"
            f"<code>{SEP}</code>\n"
            f"🔴 Found in {breach_count} public breaches\n\n"
        )


    # \u2500\u2500\u2500 Threat Intelligence \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    vt_mal    = int(ti.get("vt_malicious") or 0)
    otx_cnt   = int(ti.get("otx_pulses") or 0)
    tf_cnt    = int(ti.get("threatfox_detections") or 0)
    uh_cnt    = int(ti.get("urlhaus_detections") or 0)
    ab_score  = int(ti.get("abuseipdb_score") or 0)

    def _em_count(n: int, thresh_hi=5, thresh_lo=1) -> str:
        return "\U0001f534" if n >= thresh_hi else "\U0001f7e1" if n >= thresh_lo else "\U0001f7e2"

    threat_block = (
        f"<code>{SEP}</code>\n"
        f"\U0001f6e1 <b>THREAT INTELLIGENCE</b>\n"
        f"<code>{SEP}</code>\n"
        f"<b>Domain Verdict</b>   {ti_em} <code>{_e(ti_verdict)}</code>\n"
        f"<b>VirusTotal</b>       {_em_count(vt_mal)} <code>{vt_mal} malicious detections</code>\n"
        f"<b>AlienVault OTX</b>   {_em_count(otx_cnt)} <code>{otx_cnt} pulse(s)</code>\n"
        f"<b>ThreatFox</b>        {_em_count(tf_cnt)} <code>{tf_cnt} IOC hit(s)</code>\n"
        f"<b>URLHaus</b>          {_em_count(uh_cnt)} <code>{uh_cnt} malicious URL(s)</code>\n"
        f"<b>AbuseIPDB MX</b>     {'🔴' if ab_score >= 80 else '🟠' if ab_score >= 30 else '🟢'} <code>{ab_score}% confidence score</code>\n\n"
    )

    # \u2500\u2500\u2500 Identity Footprint \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    generated   = res.get("generated_usernames") or []
    discovered  = res.get("discovered_profiles") or []
    total_found = sum(len(c.get("profiles") or []) for c in discovered)

    footprint_block = (
        f"<code>{SEP}</code>\n"
        f"\U0001f464 <b>IDENTITY FOOTPRINT</b>\n"
        f"<code>{SEP}</code>\n"
        f"<b>Generated Handles</b>  <code>{', '.join(_e(u) for u in generated[:6])}</code>\n"
        f"<b>Profiles Found</b>     <code>{total_found}</code>\n"
    )
    if discovered:
        for entry in discovered[:3]:
            un = _e(entry.get("username") or "")
            profiles = entry.get("profiles") or []
            if profiles:
                footprint_block += f"\n<b>{un}</b>\n"
                for p in profiles[:5]:
                    footprint_block += f"  \U0001f7e2 {_e(p.get('platform', '?'))}  <code>{_e(p.get('url', '')[:60])}</code>\n"
    footprint_block += "\n"

    # \u2500\u2500\u2500 Raw Evidence Summary \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    raw_block = (
        f"<code>{SEP}</code>\n"
        f"\U0001f4cb <b>RAW EVIDENCE SUMMARY</b>\n"
        f"<code>{SEP}</code>\n"
        f"<b>Email</b>           <code>{_e(res['email'])}</code>\n"
        f"<b>Domain</b>          <code>{_e(res['domain'])}</code>\n"
        f"<b>MX Count</b>        <code>{len(mx_list)}</code>\n"
        f"<b>SPF</b>             <code>{_e(spf[:60])}</code>\n"
        f"<b>DMARC</b>           <code>{_e(dmarc[:60])}</code>\n"
        f"<b>Breaches</b>        <code>{breach_count}</code>\n"
        f"<b>Profiles</b>        <code>{total_found}</code>\n"
        f"<b>Exposure Score</b>  <code>{exp}%</code>\n\n"
    )

    # \u2500\u2500\u2500 Footer \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    footer = (
        f"<code>{SEP}</code>\n"
        f"<i>TI-Bot \u2014 Email Intelligence Engine</i>"
    )

    # \u2500\u2500\u2500 Chunk messages to Telegram 4096-char limit \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    blocks = [
        header + risk_summary + validation_block,
        domain_block,
        breach_block,
        threat_block,
        footprint_block,
        raw_block + footer,
    ]

    messages: list[str] = []
    current = ""
    for block in blocks:
        if len(current) + len(block) > 3900:
            if current:
                messages.append(current.rstrip())
            current = block
        else:
            current += block

    if current:
        messages.append(current.rstrip())

    return messages or ["⚠️ No data available."]
