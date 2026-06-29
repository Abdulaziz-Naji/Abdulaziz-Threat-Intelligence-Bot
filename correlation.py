"""
correlation.py - Full-spectrum IOC Correlation Engine.

For any IOC:
  1. Search local feed_entries database
  2. Search ioc_history (user queries)
  3. Search watchlist
  4. Resolve related IPs/domains via DNS
  5. Enrich with GeoIP / Shodan / GreyNoise
  6. Query ThreatFox for malware family associations (Phase 3)
  7. Calculate composite risk score + confidence

Output: correlation graph usable by /hunt
"""
from typing import Dict, List, Any
import api_clients
import database
import malware_intelligence as mi_engine


def _compute_confidence(sources: list, risk_scores: list) -> int:
    """
    Confidence (0-100):
      - Multiple sources = higher confidence
      - Higher risk scores = higher confidence
    """
    if not sources:
        return 0
    src_bonus = min(len(sources) * 15, 45)          # up to 45 pts for source count
    avg_risk   = sum(risk_scores) / len(risk_scores) if risk_scores else 0
    risk_bonus = int(avg_risk * 0.55)                # up to 55 pts from avg risk
    return min(src_bonus + risk_bonus, 100)


def _compute_composite_risk(feed_sources: list, watchlist_item: dict) -> int:
    """
    Composite risk from multiple feed observations.
    """
    if not feed_sources:
        return 0
    max_risk = max((s.get("risk_score") or 0) for s in feed_sources)
    src_bonus = min((len(feed_sources) - 1) * 5, 20)  # +5 per extra source
    watch_bonus = 10 if watchlist_item else 0
    return min(max_risk + src_bonus + watch_bonus, 100)


async def correlate_ioc(ioc: str, ioc_type: str) -> Dict[str, Any]:
    """
    Correlates an IOC across all local databases and external enrichment APIs.
    Returns a rich correlation graph for /hunt output.
    """
    context: Dict[str, Any] = {
        "ioc":                ioc,
        "ioc_type":           ioc_type,
        "observed_sources":   [],        # List of {source, category, risk, first_seen, last_seen}
        "ioc_history":        [],        # User query history for this IOC
        "in_watchlist":       False,
        "watchlist_risk":     None,
        "related_ips":        [],
        "related_domains":    [],
        "related_hashes":     [],
        "related_urls":       [],
        "asn":                "",
        "country":            "",
        "isp":                "",
        "city":               "",
        "shodan_ports":       [],
        "greynoise_activity": None,
        "composite_risk":     0,
        "confidence":         0,
        "verdict":            "Unknown",
        "sources_count":      0,
        "top_tags":           [],
        # Phase 3: Malware / ThreatFox associations
        "malware_families":   [],
        "tf_c2_for":          [],
        "tf_iocs":            [],
    }

    # ── 1. Local database: feed_entries ──────────────────────────────────────
    feed_sources = database.get_ioc_all_sources(ioc)
    if feed_sources:
        context["observed_sources"] = feed_sources
        context["sources_count"] = len(feed_sources)

        # Aggregate tags from all sources
        all_tags = []
        for s in feed_sources:
            import json
            try:
                tags = json.loads(s.get("tags") or "[]")
                if isinstance(tags, list):
                    all_tags.extend(tags)
            except Exception:
                pass
        # Top 5 most frequent tags
        from collections import Counter
        tag_counts = Counter(all_tags)
        context["top_tags"] = [t for t, _ in tag_counts.most_common(5)]

    # ── 1b. Local database: ioc_enrichment_cache ─────────────────────────────
    enrichment = database.get_ioc_enrichment(ioc)
    context["_enrichment_raw"] = enrichment
    context["live_intelligence_sources"] = []
    if enrichment:
        import json
        try:
            cached_srcs = json.loads(enrichment.get("sources") or "[]")
            if isinstance(cached_srcs, list):
                context["live_intelligence_sources"] = cached_srcs
        except Exception:
            pass

        # Merge tags from enrichment
        try:
            cached_tags = json.loads(enrichment.get("tags") or "[]")
            if isinstance(cached_tags, list):
                for t in cached_tags:
                    if t not in context["top_tags"]:
                        context["top_tags"].append(t)
        except Exception:
            pass

    # ── 2. Local database: ioc_history (user queries) ────────────────────────
    history = database.get_ioc_history_for(ioc)
    if history:
        context["ioc_history"] = history[:3]  # last 3 queries

    # ── 3. Watchlist check ────────────────────────────────────────────────────
    wl = database.get_watchlist_item(ioc)
    if wl:
        context["in_watchlist"] = True
        context["watchlist_risk"] = wl.get("last_risk_level", "Unknown")

    # ── 4. Composite risk & confidence ───────────────────────────────────────
    # Risk scores from feeds
    risk_scores = [s.get("risk_score") or 0 for s in feed_sources]
    # Plus score from enrichment cache if present
    if enrichment:
        risk_scores.append(enrichment.get("risk_score", 0))

    # Compute composite risk taking both feeds and enrichment cache into account
    base_risk = 0
    if feed_sources:
        max_feed_risk = max((s.get("risk_score") or 0) for s in feed_sources)
        base_risk = max(base_risk, max_feed_risk)
    if enrichment:
        base_risk = max(base_risk, enrichment.get("risk_score", 0))

    src_count = len(feed_sources) + (1 if enrichment else 0)
    src_bonus = min(max(src_count - 1, 0) * 5, 20)
    watch_bonus = 10 if wl else 0
    context["composite_risk"] = min(base_risk + src_bonus + watch_bonus, 100)

    # Confidence calculation:
    total_sources = list(set([s.get("source") for s in feed_sources] + context["live_intelligence_sources"]))
    context["confidence"] = _compute_confidence(total_sources, risk_scores)

    cr = context["composite_risk"]
    if cr >= 75:
        context["verdict"] = "Critical"
    elif cr >= 50:
        context["verdict"] = "High"
    elif cr >= 25:
        context["verdict"] = "Medium"
    elif feed_sources or enrichment:
        context["verdict"] = "Low"
    else:
        context["verdict"] = "Not Observed"

    # ── 5. External enrichment based on IOC type ─────────────────────────────
    if ioc_type == "ip":
        geo = await api_clients.geoip_lookup(ioc)
        if "error" not in geo:
            context["asn"]     = geo.get("asn", "")
            context["country"] = geo.get("country", "")
            context["isp"]     = geo.get("isp", "")
            context["city"]    = geo.get("city", "")

        shodan = await api_clients.shodan_check_ip(ioc)
        if "error" not in shodan and shodan:
            context["shodan_ports"] = shodan.get("ports", [])

        gn = await api_clients.greynoise_check_ip(ioc)
        if "error" not in gn and gn:
            context["greynoise_activity"] = gn

    elif ioc_type == "domain":
        dns = await api_clients.dns_resolve(ioc, "A")
        if "error" not in dns:
            for ans in dns.get("answers", []):
                if ans.get("type") == "A":
                    ip = ans.get("data")
                    if ip and ip not in context["related_ips"]:
                        context["related_ips"].append(ip)

        if context["related_ips"]:
            primary_ip = context["related_ips"][0]
            geo = await api_clients.geoip_lookup(primary_ip)
            if "error" not in geo:
                context["asn"]     = geo.get("asn", "")
                context["country"] = geo.get("country", "")
                context["isp"]     = geo.get("isp", "")

    elif ioc_type == "url":
        from urllib.parse import urlparse
        parsed = urlparse(ioc)
        host = parsed.netloc.split(":")[0] if parsed.netloc else ""
        if host:
            # Detect if host is IP or domain
            parts = host.split(".")
            is_ip = len(parts) == 4 and all(p.isdigit() for p in parts)
            if is_ip:
                if host not in context["related_ips"]:
                    context["related_ips"].append(host)
            else:
                if host not in context["related_domains"]:
                    context["related_domains"].append(host)
                dns = await api_clients.dns_resolve(host, "A")
                if "error" not in dns:
                    for ans in dns.get("answers", []):
                        if ans.get("type") == "A":
                            ip = ans.get("data")
                            if ip and ip not in context["related_ips"]:
                                context["related_ips"].append(ip)

    elif ioc_type in ("md5", "sha1", "sha256"):
        # For hashes: look for related IOCs in feed entries that share the same threat category
        if feed_sources:
            primary_category = feed_sources[0].get("threat_category", "")
            if primary_category:
                # Find related IPs/domains that share same category (same campaign)
                related_entries = database.get_feed_entries(
                    limit=5, ioc_type="ip"
                )
                for e in related_entries:
                    if e.get("threat_category") == primary_category:
                        if e["ioc"] not in context["related_ips"]:
                            context["related_ips"].append(e["ioc"])

                related_domains = database.get_feed_entries(
                    limit=5, ioc_type="domain"
                )
                for e in related_domains:
                    if e.get("threat_category") == primary_category:
                        if e["ioc"] not in context["related_domains"]:
                            context["related_domains"].append(e["ioc"])

    # Deduplicate
    context["related_ips"]     = list(dict.fromkeys(context["related_ips"]))[:5]
    context["related_domains"] = list(dict.fromkeys(context["related_domains"]))[:5]
    context["related_hashes"]  = list(dict.fromkeys(context["related_hashes"]))[:5]

    # ── Phase 3: ThreatFox malware association enrichment ─────────────────────
    # For IPs, domains, and URLs: look up associated malware families
    if ioc_type in ("ip", "domain", "url"):
        try:
            malware_assoc = await mi_engine.enrich_ioc_with_malware(ioc, ioc_type)
            if malware_assoc.get("found"):
                context["malware_families"] = malware_assoc.get("families", [])
                context["tf_c2_for"]        = malware_assoc.get("c2_for", [])
                context["tf_iocs"]          = malware_assoc.get("tf_iocs", [])
                # Boost risk if ThreatFox confirms malware association
                if context["malware_families"]:
                    tf_boost = min(len(context["malware_families"]) * 10, 20)
                    context["composite_risk"] = min(context["composite_risk"] + tf_boost, 100)
                    if context["composite_risk"] >= 50:
                        context["verdict"] = "High"
                    if context["composite_risk"] >= 75:
                        context["verdict"] = "Critical"
                # Add ThreatFox tags
                for ioc_entry in context["tf_iocs"]:
                    for t in (ioc_entry.get("tags") or []):
                        if t and t not in context["top_tags"]:
                            context["top_tags"].append(t)
        except Exception:
            pass  # Non-fatal: correlation still succeeds without ThreatFox data

    return context
