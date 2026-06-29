"""
report_builder.py - Builds unified Threat Intelligence Reports.

Accepts raw API results and produces:
  - Threat Score  (0–100)
  - Risk Level    (Low / Medium / High / Critical)
  - Final SOC Decision block (via decision_engine)
  - Formatted Telegram HTML message
  - Executive Summary (plain text for Teams / Email / Ticket)
"""
import html as _html
from typing import Optional
import decision_engine as de


def _e(value) -> str:
    """HTML-escape any string coming from external APIs."""
    if value is None:
        return ""
    return _html.escape(str(value))


def _get_db_context(ioc: str) -> tuple[list, bool, Optional[dict]]:
    import database as db
    try:
        feeds = db.search_feed_entries_by_ioc(ioc)
    except Exception:
        feeds = []
    try:
        in_watchlist = db.get_watchlist_item(ioc) is not None
    except Exception:
        in_watchlist = False
    try:
        cached = db.get_ioc_enrichment(ioc)
    except Exception:
        cached = None
    return feeds, in_watchlist, cached


def _make_soc_decision(
    ioc: str,
    ioc_type: str,
    vt: dict,
    abuse: dict = None,
    otx: dict = None,
) -> de.FinalDecision:
    # 1. Get DB context (feeds, watchlist, cache)
    feeds, in_watchlist, cached = _get_db_context(ioc)
    
    # 2. Extract live api statuses and values
    vt_err = bool(vt.get("error")) if vt else True
    ab_err = bool(abuse.get("error")) if abuse else True
    otx_err = bool(otx.get("error")) if otx else True
    
    # Defaults
    vt_mal = vt.get("malicious", 0) if vt and not vt_err else 0
    vt_sus = vt.get("suspicious", 0) if vt and not vt_err else 0
    vt_harm = vt.get("harmless", 0) if vt and not vt_err else 0
    vt_undet = vt.get("undetected", 0) if vt and not vt_err else 0
    vt_total = vt_mal + vt_sus + vt_harm + vt_undet
    vt_label = vt.get("threat_label", "") if vt and not vt_err else ""
    
    ab_score = abuse.get("abuse_score", 0) if abuse and not ab_err else 0
    is_tor = abuse.get("is_tor", False) if abuse and not ab_err else False
    
    otx_pulses = otx.get("pulse_count", 0) if otx and not otx_err else 0
    
    from_cache = False
    cache_risk = 0
    
    # 3. Apply Cache Fallbacks for failed sources
    if cached:
        cache_risk = cached.get("risk_score", 0)
        # If VT failed, recover from cache if available
        if vt_err and cached.get("vt_malicious", 0) > 0:
            vt_mal = cached.get("vt_malicious", 0)
            vt_total = 0
            vt_label = "Cached VT"
            from_cache = True
        # If AbuseIPDB failed, recover from cache if available
        if ab_err and cached.get("abuse_score", 0) > 0:
            ab_score = cached.get("abuse_score", 0)
            from_cache = True
        # If OTX failed, recover from cache if available
        if otx_err and cached.get("otx_pulses", 0) > 0:
            otx_pulses = cached.get("otx_pulses", 0)
            from_cache = True
            
        # If all sources failed, flag as fully from cache
        if vt_err and ab_err and otx_err:
            from_cache = True
            
    # 4. Invoke decision engine
    decision = de.make_decision(
        ioc=ioc,
        ioc_type=ioc_type,
        vt_malicious=vt_mal,
        vt_suspicious=vt_sus,
        vt_total=vt_total,
        vt_label=vt_label,
        abuse_score=ab_score,
        is_tor=is_tor,
        otx_pulses=otx_pulses,
        feed_sources=feeds,
        in_watchlist=in_watchlist,
        from_cache=from_cache,
        cache_risk=cache_risk,
        vt_available=not vt_err,
        abuse_available=not ab_err,
        otx_available=not otx_err,
    )
    return decision


# ─── Risk thresholds ──────────────────────────────────────────────────────────

def compute_threat_score(
    vt_malicious: int  = 0,
    vt_suspicious: int = 0,
    abuse_score: int   = 0,
    otx_pulses: int    = 0,
) -> int:
    """Composite threat score 0-100."""
    score = 0
    # VT malicious: up to 50 pts
    score += min(vt_malicious * 5, 50)
    # VT suspicious: up to 10 pts
    score += min(vt_suspicious * 2, 10)
    # AbuseIPDB: up to 30 pts  (score is 0-100, map to 0-30)
    score += int(abuse_score * 0.30)
    # OTX pulses: up to 10 pts
    score += min(otx_pulses * 2, 10)
    return min(score, 100)


def risk_level(threat_score: int) -> tuple[str, str]:
    """Returns (level_name, emoji)."""
    if threat_score >= 75:
        return "Critical", "🔴"
    if threat_score >= 50:
        return "High", "🟠"
    if threat_score >= 25:
        return "Medium", "🟡"
    return "Low", "🟢"


# ─── Unified report for IP ────────────────────────────────────────────────────

# ─── Unified report for IP ────────────────────────────────────────────────────

def _parse_rdap_ip_info(rdap_data: dict) -> dict:
    if not rdap_data or "error" in rdap_data or not isinstance(rdap_data, dict):
        return {}
    
    info = {
        "netname": rdap_data.get("name", ""),
        "inetnum": f"{rdap_data.get('startAddress', '')} - {rdap_data.get('endAddress', '')}".strip(" -"),
        "country": rdap_data.get("country", ""),
        "parent_network": rdap_data.get("parentHandle", ""),
        "organization": "",
        "abuse_contact": "",
        "admin_contact": "",
        "tech_contact": "",
        "created_date": "",
        "updated_date": "",
    }
    
    for ev in rdap_data.get("events", []):
        if not isinstance(ev, dict): continue
        action = ev.get("eventAction", "")
        date = ev.get("eventDate", "")
        if date:
            date = date[:10]
            if action == "registration":
                info["created_date"] = date
            elif action == "last changed":
                info["updated_date"] = date
                
    def extract_vcard_info(entity):
        contact = {"name": "", "email": "", "phone": ""}
        vcard_arr = entity.get("vcardArray", [])
        if len(vcard_arr) > 1 and isinstance(vcard_arr[1], list):
            for field in vcard_arr[1]:
                if not isinstance(field, list) or len(field) < 4:
                    continue
                type_name = field[0]
                val = field[3]
                if type_name == "fn":
                    contact["name"] = str(val)
                elif type_name == "email":
                    contact["email"] = str(val)
                elif type_name == "tel":
                    contact["phone"] = str(val)
        return contact

    def traverse_entities(entities):
        if not isinstance(entities, list): return
        for ent in entities:
            if not isinstance(ent, dict): continue
            roles = ent.get("roles", [])
            contact = extract_vcard_info(ent)
            
            if "registrant" in roles or "registrant" in ent.get("handle", "").lower():
                if contact["name"] and not info["organization"]:
                    info["organization"] = contact["name"]
            
            if "abuse" in roles:
                if contact["email"]:
                    info["abuse_contact"] = contact["email"]
                elif contact["name"] and "@" in contact["name"]:
                    info["abuse_contact"] = contact["name"]
            
            if "administrative" in roles:
                info["admin_contact"] = contact["email"] or contact["name"]
                
            if "technical" in roles:
                info["tech_contact"] = contact["email"] or contact["name"]
                
            if ent.get("entities"):
                traverse_entities(ent["entities"])
                
    traverse_entities(rdap_data.get("entities", []))
    
    if not info["organization"]:
        for ent in rdap_data.get("entities", []):
            if not isinstance(ent, dict): continue
            contact = extract_vcard_info(ent)
            if contact["name"]:
                info["organization"] = contact["name"]
                break
                
    return info


def build_ip_report(
    ioc: str,
    vt: dict,
    abuse: dict,
    otx: dict,
    geo: dict,
    shodan: dict = None,
    greynoise: dict = None,
    rdap: dict = None,
) -> tuple[str, dict]:
    import socket
    import database as db
    
    # Defaults for optional inputs
    vt = vt or {}
    abuse = abuse or {}
    otx = otx or {}
    geo = geo or {}
    shodan = shodan or {}
    greynoise = greynoise or {}
    rdap = rdap or {}
    
    # 1. Reverse DNS
    try:
        rdns = socket.gethostbyaddr(ioc)[0]
    except Exception:
        rdns = "N/A"
        
    # 2. Local DB feeds & watchlist
    feeds = db.search_feed_entries_by_ioc(ioc)
    in_watchlist = db.get_watchlist_item(ioc) is not None
    
    # Parse RDAP WHOIS data
    rdap_info = _parse_rdap_ip_info(rdap)
    
    # Geolocation / ASN
    country = geo.get("country") or vt.get("country") or abuse.get("country_code") or rdap_info.get("country") or "N/A"
    asn = geo.get("asn") or vt.get("asn") or "N/A"
    isp = geo.get("isp") or abuse.get("isp") or "N/A"
    org = geo.get("org") or rdap_info.get("organization") or "N/A"
    city = geo.get("city") or otx.get("city") or "N/A"
    region = geo.get("region", "N/A")
    timezone = geo.get("timezone", "N/A")
    lat = geo.get("lat")
    lon = geo.get("lon")
    coords = f"{lat}, {lon}" if (lat and lon) else "N/A"
    network_range = rdap_info.get("inetnum") or vt.get("network") or "N/A"
    
    # Context classification
    context = {
        "is_vpn": False,
        "is_proxy": False,
        "is_tor": bool(abuse.get("is_tor", False)),
        "is_hosting": False,
        "is_residential": False,
        "is_cdn": False,
        "is_gov": False,
        "is_uni": False,
        "is_enterprise": False,
        "type_desc": "Commercial / Enterprise",
    }
    
    isp_l = str(isp).lower()
    org_l = str(org).lower()
    usage_l = str(abuse.get("usage_type") or "").lower()
    
    if context["is_tor"] or "tor" in isp_l or "tor" in org_l:
        context["is_tor"] = True
        context["type_desc"] = "Tor Exit Node"
    if any(k in isp_l or k in org_l for k in ("vpn", "nordvpn", "expressvpn", "mullvad", "proxy", "hidemyass", "protonvpn")) or "vpn" in usage_l or "proxy" in usage_l:
        context["is_vpn"] = True
        context["type_desc"] = "VPN / Proxy Service"
    if any(k in isp_l or k in org_l for k in ("hosting", "digitalocean", "linode", "aws", "amazon", "google cloud", "gcp", "azure", "microsoft", "hetzner", "ovh", "leaseweb", "choopa", "vultr", "m247", "flokinet")) or "hosting" in usage_l or "datacenter" in usage_l:
        context["is_hosting"] = True
        context["type_desc"] = "Cloud / Hosting Provider"
    if any(k in isp_l or k in org_l for k in ("cloudflare", "fastly", "akamai", "cloudfront", "cdn")) or "cdn" in usage_l:
        context["is_cdn"] = True
        context["type_desc"] = "Content Delivery Network (CDN)"
    if any(k in isp_l or k in org_l for k in ("telecom", "isp", "residential", "comcast", "charter", "at&t", "verizon", "orange", "bt", "rogers")) or "residential" in usage_l:
        context["is_residential"] = True
        context["type_desc"] = "Residential ISP"
    if "gov" in isp_l or "gov" in org_l or "government" in usage_l:
        context["is_gov"] = True
        context["type_desc"] = "Government Network"
    if "edu" in isp_l or "edu" in org_l or "university" in usage_l or "college" in usage_l:
        context["is_uni"] = True
        context["type_desc"] = "Educational / University Network"

    # Reputation values
    vt_mal = vt.get("malicious", 0) if vt and not vt.get("error") else 0
    vt_total = vt_mal + vt.get("suspicious", 0) + vt.get("harmless", 0) + vt.get("undetected", 0) if vt and not vt.get("error") else 0
    ab_score = abuse.get("abuse_score", 0) if abuse and not abuse.get("error") else 0
    ab_rep = abuse.get("total_reports", 0) if abuse and not abuse.get("error") else 0
    otx_cnt = otx.get("pulse_count", 0) if otx and not otx.get("error") else 0
    
    gn_noise = greynoise.get("noise", False) if greynoise and not greynoise.get("error") else False
    gn_class = greynoise.get("classification", "N/A") if greynoise and not greynoise.get("error") else "N/A"
    
    sh_ports = shodan.get("ports", []) if shodan and not shodan.get("error") else []
    sh_hostnames = shodan.get("hostnames", []) if shodan and not shodan.get("error") else []
    
    # Threat Feeds agreement & Attack Intelligence
    malware_family = ""
    activity_types = []
    
    if otx and not otx.get("error") and otx.get("pulses"):
        for p in otx["pulses"][:3]:
            tags = p.get("tags", [])
            for t in tags:
                if t.lower() not in activity_types:
                    activity_types.append(t)
            if not malware_family and p.get("malware_family"):
                malware_family = p.get("malware_family")
                
    feed_sources_list = []
    for f in feeds:
        feed_sources_list.append(f.get("source", "").upper())
        cat = f.get("threat_category", "")
        if cat and cat not in activity_types:
            activity_types.append(cat)
            
    if "threatfox" in [s.lower() for s in feed_sources_list]:
        for f in feeds:
            if f.get("source") == "threatfox":
                try:
                    import json
                    rd = json.loads(f.get("raw_data") or "{}")
                    malware_family = rd.get("malware_family") or malware_family
                except Exception:
                    pass

    # Timeline calculations
    from datetime import datetime, timezone
    first_seen_list = []
    last_seen_list = []
    
    if rdap_info.get("created_date"):
        first_seen_list.append(rdap_info["created_date"])
    for f in feeds:
        if f.get("first_seen"): first_seen_list.append(f["first_seen"][:10])
        if f.get("last_seen"): last_seen_list.append(f["last_seen"][:10])
        
    first_seen = min(first_seen_list) if first_seen_list else "N/A"
    last_seen = max(last_seen_list) if last_seen_list else datetime.now(timezone.utc).strftime("%Y-%m-%d")
    last_mal_activity = last_seen if (vt_mal > 0 or ab_score > 0 or feeds) else "N/A"
    
    # Call Decision Engine
    decision = de.make_decision(
        ioc=ioc,
        ioc_type="ip",
        vt_malicious=vt_mal,
        vt_suspicious=vt.get("suspicious", 0) if vt and not vt.get("error") else 0,
        vt_total=vt_total,
        vt_label=vt.get("threat_label", "") if vt else "",
        abuse_score=ab_score,
        is_tor=context["is_tor"],
        otx_pulses=otx_cnt,
        feed_sources=feeds,
        in_watchlist=in_watchlist,
        from_cache=False,
    )
    
    # Format response
    msg = ""
    # 1. General Information
    msg += (
        f"<b>1. GENERAL INFORMATION</b>\n"
        f"• <b>IP Address:</b> <code>{_e(ioc)}</code>\n"
        f"• <b>IP Version:</b> <code>IPv4</code>\n"
        f"• <b>Reverse DNS:</b> <code>{_e(rdns)}</code>\n"
        f"• <b>ASN:</b> <code>AS{_e(asn)}</code>\n"
        f"• <b>Organization:</b> <code>{_e(org)}</code>\n"
        f"• <b>ISP:</b> <code>{_e(isp)}</code>\n"
        f"• <b>Hosting Provider:</b> <code>{_e(isp) if context['is_hosting'] else 'N/A'}</code>\n"
        f"• <b>Country/Region/City:</b> <code>{_e(country)} / {_e(region)} / {_e(city)}</code>\n"
        f"• <b>Timezone / Coords:</b> <code>{_e(timezone)} / {_e(coords)}</code>\n"
        f"• <b>Network CIDR:</b> <code>{_e(network_range)}</code>\n\n"
    )
    
    # 2. WHOIS Intelligence
    msg += (
        f"<b>2. WHOIS INTELLIGENCE</b>\n"
        f"• <b>Netname:</b> <code>{_e(rdap_info.get('netname', 'N/A'))}</code>\n"
        f"• <b>Organization:</b> <code>{_e(rdap_info.get('organization', 'N/A'))}</code>\n"
        f"• <b>Country:</b> <code>{_e(rdap_info.get('country', 'N/A'))}</code>\n"
        f"• <b>Abuse Contact:</b> <code>{_e(rdap_info.get('abuse_contact', 'N/A'))}</code>\n"
        f"• <b>Admin Contact:</b> <code>{_e(rdap_info.get('admin_contact', 'N/A'))}</code>\n"
        f"• <b>Tech Contact:</b> <code>{_e(rdap_info.get('tech_contact', 'N/A'))}</code>\n"
        f"• <b>Created Date:</b> <code>{_e(rdap_info.get('created_date', 'N/A'))}</code>\n"
        f"• <b>Updated Date:</b> <code>{_e(rdap_info.get('updated_date', 'N/A'))}</code>\n"
        f"• <b>Parent Network:</b> <code>{_e(rdap_info.get('parent_network', 'N/A'))}</code>\n\n"
    )
    
    # 3. Reputation Intelligence
    tf_status = "Observed" if "threatfox" in [s.lower() for s in feed_sources_list] else "No Match"
    uh_status = "Observed" if "urlhaus" in [s.lower() for s in feed_sources_list] else "No Match"
    
    msg += (
        f"<b>3. REPUTATION INTELLIGENCE</b>\n"
        f"• <b>VirusTotal:</b> <code>{vt_mal}/{vt_total} vendors detected</code>\n"
        f"• <b>AbuseIPDB:</b> <code>{ab_score}% confidence ({ab_rep} reports)</code>\n"
        f"• <b>OTX Pulses:</b> <code>{otx_cnt} pulses</code>\n"
        f"• <b>ThreatFox:</b> <code>{tf_status}</code>\n"
        f"• <b>URLhaus:</b> <code>{uh_status}</code>\n"
        f"• <b>GreyNoise:</b> <code>Noise: {gn_noise} (Class: {gn_class})</code>\n"
        f"• <b>Spamhaus / Feeds:</b> <code>{', '.join(set(feed_sources_list)) or 'No active sightings'}</code>\n\n"
    )
    
    # 4. Passive Intelligence
    ports_str = ", ".join(str(p) for p in sh_ports) or "None detected"
    hosts_str = ", ".join(sh_hostnames) or "None detected"
    
    hist_domains = list(set([f.get("ioc") for f in feeds if f.get("ioc_type") == "domain"] + sh_hostnames))[:3]
    hist_dom_str = ", ".join(hist_domains) or "None detected"
    
    msg += (
        f"<b>4. PASSIVE INTELLIGENCE</b>\n"
        f"• <b>Open Ports:</b> <code>{_e(ports_str)}</code>\n"
        f"• <b>Historical Hostnames:</b> <code>{_e(hosts_str)}</code>\n"
        f"• <b>Historical Domains:</b> <code>{_e(hist_dom_str)}</code>\n"
        f"• <b>Services / OS:</b> <code>{_e(shodan.get('os', 'Unknown OS'))}</code>\n\n"
    )
    
    # 5. Context
    infra_types = []
    if context["is_tor"]: infra_types.append("Tor Exit Node")
    if context["is_vpn"]: infra_types.append("VPN")
    if context["is_proxy"]: infra_types.append("Proxy")
    if context["is_hosting"]: infra_types.append("Hosting Provider")
    if context["is_residential"]: infra_types.append("Residential ISP")
    if context["is_cdn"]: infra_types.append("CDN")
    if context["is_gov"]: infra_types.append("Government")
    if context["is_uni"]: infra_types.append("University")
    if not infra_types: infra_types.append("Enterprise / Commercial")
    
    msg += (
        f"<b>5. CONTEXT</b>\n"
        f"• <b>Infrastructure Type:</b> <code>{', '.join(infra_types)}</code>\n"
        f"• <b>Usage:</b> <code>{_e(context['type_desc'])}</code>\n\n"
    )
    
    # 6. Attack Intelligence
    act_str = ", ".join(activity_types) or "No active campaigns"
    msg += (
        f"<b>6. ATTACK INTELLIGENCE</b>\n"
        f"• <b>Malware Family:</b> <code>{_e(malware_family or 'N/A')}</code>\n"
        f"• <b>Known Activity:</b> <code>{_e(act_str)}</code>\n\n"
    )
    
    # 7. Timeline
    msg += (
        f"<b>7. TIMELINE</b>\n"
        f"• <b>First Seen:</b> <code>{_e(first_seen)}</code>\n"
        f"• <b>Last Seen:</b> <code>{_e(last_seen)}</code>\n"
        f"• <b>Last Malicious Activity:</b> <code>{_e(last_mal_activity)}</code>\n\n"
        f"<i>Report generated by TI-Bot | UTC</i>"
    )
    
    result = {
        "risk_level": decision.verdict,
        "threat_score": decision.risk_score,
        "vt_malicious": vt_mal,
        "abuse_score": ab_score,
        "otx_pulses": otx_cnt,
        "country": country,
        "asn": asn,
        "soc_verdict": decision.verdict,
        "soc_risk_score": decision.risk_score,
        "soc_confidence": decision.confidence,
        "soc_action": decision.action,
    }
    return msg, result



# ─── Unified report for Domain ────────────────────────────────────────────────

def build_domain_report(
    ioc: str,
    vt: dict,
    otx: dict,
    dns: dict,
    rdap: dict,
) -> tuple[str, dict]:
    vt_mal  = vt.get("malicious", 0) if vt else 0
    vt_sus  = vt.get("suspicious", 0) if vt else 0
    vt_harm = vt.get("harmless", 0) if vt else 0
    vt_undet= vt.get("undetected", 0) if vt else 0
    vt_rep  = vt.get("reputation", 0) if vt else 0
    otx_cnt = otx.get("pulse_count", 0) if otx else 0

    ts     = compute_threat_score(vt_mal, vt_sus, 0, otx_cnt)
    rl, em = risk_level(ts)

    dns_answers = dns.get("answers", []) if dns else []
    dns_text = ""
    for a in dns_answers[:5]:
        dns_text += f"  • <code>{a['data']}</code> ({a['type']})\n"
    if dns and dns.get("nx"):
        dns_text = "  ⚠️ NXDOMAIN — does not resolve\n"
    if not dns_text:
        dns_text = "  N/A\n"

    registrar = (rdap.get("registrar") if rdap else "") or (vt.get("registrar") if vt else "") or "N/A"
    registered = (rdap.get("registered", "")[:10] if rdap else "") or "N/A"
    expiration = (rdap.get("expiration", "")[:10] if rdap else "") or "N/A"
    nameservers = rdap.get("nameservers", [])[:3] if rdap else []
    ns_text = "\n".join(f"  • <code>{ns}</code>" for ns in nameservers) or "  N/A"

    categories = vt.get("categories", {}) if vt else {}
    cat_text = _e(", ".join(set(categories.values()))[:80]) or "N/A"

    pulses_text = ""
    if otx and otx.get("pulses"):
        pulse_names = [_e(p.get("name", "?"))[:60] for p in otx["pulses"][:3]]
        pulses_text = "\n".join(f"  • {p}" for p in pulse_names)

    sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"

    msg = (
        f"<b>🔍 Threat Intelligence Report</b>\n"
        f"<code>{sep}</code>\n\n"
        f"<b>IOC:</b>  <code>{_e(ioc)}</code>\n"
        f"<b>Type:</b> 🔗 Domain\n\n"
        f"<b>📊 Risk Assessment</b>\n"
        f"<code>{sep}</code>\n"
        f"<b>Threat Score:</b>  <code>{ts}/100</code>\n"
        f"<b>Risk Level:</b>    {em} <b>{rl}</b>\n\n"
        f"<b>🛡 VirusTotal</b>\n"
    )
    if vt and vt.get("error"):
        msg += "  ⚠️ [Unavailable]\n"
    else:
        msg += (
            f"  🔴 Malicious:  <b>{vt_mal}</b>\n"
            f"  🟡 Suspicious: <b>{vt_sus}</b>\n"
            f"  🟢 Harmless:   <b>{vt_harm}</b>\n"
            f"  ⚪ Undetected: <b>{vt_undet}</b>\n"
            f"  📈 Reputation: <b>{vt_rep}</b>\n"
            f"  🏷 Categories: <i>{cat_text}</i>\n"
        )

    msg += f"\n<b>🌀 AlienVault OTX</b>\n"
    if otx and otx.get("error"):
        msg += "  ⚠️ [Unavailable]\n"
    else:
        msg += f"  📡 OTX Pulses:  <b>{otx_cnt}</b>\n"
        if pulses_text:
            msg += f"  <i>Recent:</i>\n{pulses_text}\n"

    msg += (
        f"\n<b>🌐 DNS Records</b>\n"
        f"{dns_text}"
        f"\n<b>📋 WHOIS / RDAP</b>\n"
        f"  🏢 Registrar:   <b>{_e(registrar)}</b>\n"
        f"  📅 Registered:  <b>{_e(registered)}</b>\n"
        f"  ⏳ Expires:     <b>{_e(expiration)}</b>\n"
        f"  🖥 Nameservers:\n{ns_text}\n"
        f"\n<code>{sep}</code>\n"
        f"<i>Report generated by TI-Bot | UTC</i>"
    )

    decision = _make_soc_decision(ioc, "domain", vt, None, otx)
    msg += "\n" + soc_block

    result = {
        "risk_level": decision.verdict,
        "threat_score": decision.risk_score,
        "vt_malicious": vt_mal,
        "abuse_score": 0,
        "otx_pulses": otx_cnt,
        "country": "",
        "asn": "",
        "soc_verdict": decision.verdict,
        "soc_risk_score": decision.risk_score,
        "soc_confidence": decision.confidence,
        "soc_action": decision.action,
    }
    return msg, result


# ─── Unified report for Hash ──────────────────────────────────────────────────

def build_hash_report(
    ioc: str,
    ioc_type: str,
    vt: dict,
    otx: dict,
) -> tuple[str, dict]:
    vt_mal  = vt.get("malicious", 0) if vt else 0
    vt_sus  = vt.get("suspicious", 0) if vt else 0
    vt_harm = vt.get("harmless", 0) if vt else 0
    vt_undet= vt.get("undetected", 0) if vt else 0
    otx_cnt = otx.get("pulse_count", 0) if otx else 0

    # Ensure integer values
    vt_mal  = int(vt_mal) if isinstance(vt_mal, (int, float)) else 0
    vt_sus  = int(vt_sus) if isinstance(vt_sus, (int, float)) else 0
    vt_harm = int(vt_harm) if isinstance(vt_harm, (int, float)) else 0
    vt_undet= int(vt_undet) if isinstance(vt_undet, (int, float)) else 0
    otx_cnt = int(otx_cnt) if isinstance(otx_cnt, (int, float)) else 0

    ts     = compute_threat_score(vt_mal, vt_sus, 0, otx_cnt)
    rl, em = risk_level(ts)

    pulses_text = ""
    otx_pulses_list = otx.get("pulses") if otx else None
    if isinstance(otx_pulses_list, list) and otx_pulses_list:
        pulse_names = [_e(p.get("name", "?"))[:60] for p in otx_pulses_list[:3] if isinstance(p, dict)]
        pulses_text = "\n".join(f"  • {p}" for p in pulse_names if p)

    sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
    type_emoji = {"md5": "🔒 MD5", "sha1": "🔒 SHA1", "sha256": "🔒 SHA256"}.get(ioc_type, "🔒 Hash")
    # Safe display: show first 20 chars + ellipsis for long hashes
    ioc_display = _e(ioc[:20]) + "…" if len(ioc) > 20 else _e(ioc)

    msg = (
        f"<b>🔍 Threat Intelligence Report</b>\n"
        f"<code>{sep}</code>\n\n"
        f"<b>IOC:</b>  <code>{ioc_display}</code>\n"
        f"<b>Type:</b> {type_emoji}\n\n"
        f"<b>📊 Risk Assessment</b>\n"
        f"<code>{sep}</code>\n"
        f"<b>Threat Score:</b>  <code>{ts}/100</code>\n"
        f"<b>Risk Level:</b>    {em} <b>{rl}</b>\n\n"
        f"<b>🛡 VirusTotal</b>\n"
    )
    if vt and vt.get("error"):
        msg += "  ⚠️ [Unavailable]\n"
    else:
        threat_label = _e(vt.get("threat_label") or "") if vt else ""
        file_name    = _e(vt.get("file_name") or "") if vt else ""
        file_size    = vt.get("file_size", 0) if vt else 0
        file_size    = int(file_size) if isinstance(file_size, (int, float)) else 0
        magic        = _e(vt.get("magic") or "") if vt else ""
        msg += (
            f"  🔴 Malicious:   <b>{vt_mal}</b>\n"
            f"  🟡 Suspicious:  <b>{vt_sus}</b>\n"
            f"  🟢 Harmless:    <b>{vt_harm}</b>\n"
            f"  ⚪ Undetected:  <b>{vt_undet}</b>\n"
        )
        if threat_label:
            msg += f"  ☠️ Threat Label: <b>{threat_label}</b>\n"
        if file_name:
            msg += f"  📄 File Name:   <code>{file_name[:60]}</code>\n"
        if file_size:
            msg += f"  📦 File Size:   <b>{file_size:,} bytes</b>\n"
        if magic:
            msg += f"  🔬 Magic:       <i>{magic[:60]}</i>\n"
        
        # Hashes cross-reference
        md5_val = vt.get("md5") if vt else None
        if md5_val:
            msg += f"\n<b>🔗 Hash Cross-Reference</b>\n"
            msg += f"  MD5:    <code>{_e(md5_val)}</code>\n"
            
            sha1_val = vt.get("sha1") if vt else None
            if sha1_val:
                msg += f"  SHA1:   <code>{_e(sha1_val)}</code>\n"
                
            sha256_val = vt.get("sha256") if vt else None
            if sha256_val:
                sha256_short = _e(sha256_val[:30])
                msg += f"  SHA256: <code>{sha256_short}…</code>\n"

    msg += f"\n<b>🌀 AlienVault OTX</b>\n"
    if otx and otx.get("error"):
        msg += "  ⚠️ [Unavailable]\n"
    else:
        malware_family = _e(otx.get("malware_family") or "") if otx else ""
        msg += f"  📡 OTX Pulses: <b>{otx_cnt}</b>\n"
        if malware_family:
            msg += f"  🦠 Family:    <b>{malware_family}</b>\n"
        if pulses_text:
            msg += f"  <i>Recent:</i>\n{pulses_text}\n"

    msg += (
        f"\n<code>{sep}</code>\n"
        f"<i>Report generated by TI-Bot | UTC</i>"
    )

    decision = _make_soc_decision(ioc, ioc_type, vt, None, otx)
    msg += "\n" + soc_block

    result = {
        "risk_level": decision.verdict,
        "threat_score": decision.risk_score,
        "vt_malicious": vt_mal,
        "abuse_score": 0,
        "otx_pulses": otx_cnt,
        "country": "",
        "asn": "",
        "soc_verdict": decision.verdict,
        "soc_risk_score": decision.risk_score,
        "soc_confidence": decision.confidence,
        "soc_action": decision.action,
    }
    return msg, result


# ─── Unified report for URL ───────────────────────────────────────────────────

def build_url_report(
    ioc: str,
    vt: dict,
    otx: dict,
) -> tuple[str, dict]:
    vt_mal  = vt.get("malicious", 0) if vt else 0
    vt_sus  = vt.get("suspicious", 0) if vt else 0
    vt_harm = vt.get("harmless", 0) if vt else 0
    vt_undet= vt.get("undetected", 0) if vt else 0
    otx_cnt = otx.get("pulse_count", 0) if otx else 0

    ts     = compute_threat_score(vt_mal, vt_sus, 0, otx_cnt)
    rl, em = risk_level(ts)

    pulses_text = ""
    if otx and otx.get("pulses"):
        pulse_names = [p.get("name", "?")[:50] for p in otx["pulses"][:3]]
        pulses_text = "\n".join(f"  • {p}" for p in pulse_names)

    sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
    display_url = ioc[:60] + "…" if len(ioc) > 60 else ioc

    msg = (
        f"<b>🔍 Threat Intelligence Report</b>\n"
        f"<code>{sep}</code>\n\n"
        f"<b>IOC:</b>  <code>{display_url}</code>\n"
        f"<b>Type:</b> 🔗 URL\n\n"
        f"<b>📊 Risk Assessment</b>\n"
        f"<code>{sep}</code>\n"
        f"<b>Threat Score:</b>  <code>{ts}/100</code>\n"
        f"<b>Risk Level:</b>    {em} <b>{rl}</b>\n\n"
        f"<b>🛡 VirusTotal</b>\n"
    )
    if vt and vt.get("error"):
        if vt.get("submitted"):
            msg += f"  ⏳ {vt['error']}\n"
        else:
            msg += "  ⚠️ [Unavailable]\n"
    else:
        final_url = vt.get("final_url", "") if vt else ""
        title     = vt.get("title", "") if vt else ""
        msg += (
            f"  🔴 Malicious:   <b>{vt_mal}</b>\n"
            f"  🟡 Suspicious:  <b>{vt_sus}</b>\n"
            f"  🟢 Harmless:    <b>{vt_harm}</b>\n"
            f"  ⚪ Undetected:  <b>{vt_undet}</b>\n"
        )
        if title:
            msg += f"  📄 Title: <i>{title[:80]}</i>\n"
        if final_url and final_url != ioc:
            msg += f"  🔄 Final URL: <code>{final_url[:60]}</code>\n"

    msg += f"\n<b>🌀 AlienVault OTX</b>\n"
    if otx and otx.get("error"):
        msg += "  ⚠️ [Unavailable]\n"
    else:
        msg += f"  📡 OTX Pulses: <b>{otx_cnt}</b>\n"
        if pulses_text:
            msg += f"  <i>Recent:</i>\n{pulses_text}\n"

    msg += (
        f"\n<code>{sep}</code>\n"
        f"<i>Report generated by TI-Bot | UTC</i>"
    )

    decision = _make_soc_decision(ioc, "url", vt, None, otx)
    msg += "\n" + soc_block

    result = {
        "risk_level": decision.verdict,
        "threat_score": decision.risk_score,
        "vt_malicious": vt_mal,
        "abuse_score": 0,
        "otx_pulses": otx_cnt,
        "country": "",
        "asn": "",
        "soc_verdict": decision.verdict,
        "soc_risk_score": decision.risk_score,
        "soc_confidence": decision.confidence,
        "soc_action": decision.action,
    }
    return msg, result


# ─── Executive Summary (plain text) ───────────────────────────────────────────

def build_executive_summary(
    ioc: str,
    ioc_type: str,
    result: dict,
) -> str:
    rl = result.get("risk_level", "Unknown")
    ts = result.get("threat_score", 0)
    em = {"Low": "🟢", "Medium": "🟡", "High": "🟠", "Critical": "🔴"}.get(rl, "⚪")
    sep = "─" * 40

    summary = (
        f"THREAT INTELLIGENCE EXECUTIVE SUMMARY\n"
        f"{sep}\n"
        f"IOC:          {ioc}\n"
        f"Type:         {ioc_type.upper()}\n"
        f"Threat Score: {ts}/100\n"
        f"Risk Level:   {rl}\n"
        f"{sep}\n"
        f"VT Malicious: {result.get('vt_malicious', 'N/A')}\n"
        f"Abuse Score:  {result.get('abuse_score', 'N/A')}/100\n"
        f"OTX Pulses:   {result.get('otx_pulses', 'N/A')}\n"
        f"Country:      {result.get('country', 'N/A')}\n"
        f"ASN:          {result.get('asn', 'N/A')}\n"
        f"{sep}\n"
        f"Verdict: {em} {rl.upper()} RISK\n"
        f"Generated by: Threat Intelligence Bot\n"
    )
    return summary


def build_daily_report() -> str:
    """Builds the Daily Executive Summary HTML message."""
    import database as db
    
    counts = db.get_feed_count_by_type(hours=24)
    hashes = counts.get("sha256", 0) + counts.get("md5", 0) + counts.get("sha1", 0) + counts.get("hash", 0)
    domains = counts.get("domain", 0)
    ips = counts.get("ip", 0)
    urls = counts.get("url", 0)
    cves = counts.get("cve", 0)
    
    top_threats = db.get_top_threats(limit=5, hours=24)
    top_families = db.get_top_malware_families(limit=5, hours=24)
    
    sources = db.get_all_feed_sources()
    active_sources = [s for s in sources if s.get("status") == "ok"]
    
    sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    msg = (
        f"☀️ <b>Daily Executive Threat Brief</b>\n"
        f"<code>{sep}</code>\n\n"
        f"<b>📊 24h Activity Summary:</b>\n"
        f"  • New Hashes: <b>{hashes}</b>\n"
        f"  • New Domains: <b>{domains}</b>\n"
        f"  • New IPs: <b>{ips}</b>\n"
        f"  • New URLs: <b>{urls}</b>\n"
        f"  • New CVEs: <b>{cves}</b>\n\n"
    )
    
    if top_threats:
        msg += "🔥 <b>Top Critical Threats:</b>\n"
        for t in top_threats:
            categories = t.get("categories") or "Unknown"
            msg += f"  • <code>{t['ioc']}</code> ({t['ioc_type'].upper()})\n    Risk: <b>{t['max_risk']}/100</b> | Type: <i>{categories}</i>\n"
        msg += "\n"
        
    if top_families:
        msg += "🦠 <b>Top Malware Families:</b>\n"
        for f in top_families:
            msg += f"  • <b>{f['threat_category']}</b>: {f['cnt']} detections\n"
        msg += "\n"
        
    if active_sources:
        msg += "📡 <b>Active Feeds:</b>\n"
        msg += ", ".join(s['display_name'] for s in active_sources[:5]) + "\n\n"
        
    msg += (
        f"<code>{sep}</code>\n"
        f"<i>Generated by Threat Intelligence Bot</i>"
    )
    return msg


def build_weekly_report() -> str:
    """Builds the Weekly Executive Report HTML message."""
    import database as db
    
    stats = db.get_weekly_stats()
    
    new_this_week = stats.get("new_this_week", 0)
    new_last_week = stats.get("new_last_week", 0)
    
    diff = new_this_week - new_last_week
    if new_last_week > 0:
        pct = (diff / new_last_week) * 100
        trend_str = f"{'+' if diff >= 0 else ''}{diff} ({'+' if pct >= 0 else ''}{pct:.1f}%)"
    else:
        trend_str = f"{'+' if diff >= 0 else ''}{diff} (N/A)"
        
    top_sources = stats.get("top_sources", [])
    top_families = stats.get("top_families", [])
    high_risk_count = stats.get("high_risk_count", 0)
    by_type = stats.get("by_type", {})
    
    sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    msg = (
        f"📊 <b>Weekly Executive Threat Intelligence Report</b>\n"
        f"<code>{sep}</code>\n\n"
        f"<b>📈 Activity & Trends:</b>\n"
        f"  • Total IOCs Collected: <b>{new_this_week}</b>\n"
        f"  • Trend vs Last Week: <b>{trend_str}</b>\n"
        f"  • High-Risk Indicators (>=75): <b>{high_risk_count}</b>\n\n"
    )
    
    msg += "🗂 <b>Breakdown by IOC Type:</b>\n"
    for t_type, cnt in by_type.items():
        msg += f"  • {t_type.upper()}: <b>{cnt}</b>\n"
    msg += "\n"
        
    if top_families:
        msg += "🦠 <b>Top Malware Families:</b>\n"
        for f in top_families:
            msg += f"  • <b>{f['threat_category']}</b>: {f['cnt']} detections\n"
        msg += "\n"
        
    if top_sources:
        msg += "📡 <b>Top Threat Feeds:</b>\n"
        for s in top_sources:
            msg += f"  • <b>{s['source'].upper()}</b>: {s['cnt']} IOCs\n"
        msg += "\n"
        
    msg += (
        f"<code>{sep}</code>\n"
        f"<i>Weekly Briefing | Threat Intelligence Bot</i>"
    )
    return msg

