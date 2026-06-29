"""
handlers/check.py - /check <ioc> unified analysis handler.
Phase 12: Routes through ti_report_builder (evidence-only TI reports).
"""
import asyncio
import hashlib
import html as html_lib
from urllib.parse import urlparse
from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

import ioc_classifier as clf
import api_clients as api
import ti_report_builder as ti_rb
import report_builder as rb       # kept for legacy callbacks
import database as db
import json

# ── IOC token store ──────────────────────────────────────────────────────────
# Telegram callback_data is limited to 64 bytes.
# We map full IOCs to short 8-char tokens so callback_data always fits.
_IOC_TOKEN_STORE: dict[str, str] = {}   # token → full_ioc


def _ioc_token(ioc: str) -> str:
    """Return an 8-char hex token for *ioc*, registering it in the store."""
    token = hashlib.md5(ioc.encode()).hexdigest()[:8]
    _IOC_TOKEN_STORE[token] = ioc
    return token


def resolve_ioc_token(token: str) -> str | None:
    """Resolve an 8-char token back to the original IOC string."""
    return _IOC_TOKEN_STORE.get(token)





async def check_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.effective_message
    if not message:
        return

    if not context.args:
        await message.reply_text(
            "⚠️ Usage: <code>/check &lt;ip | domain | url | hash&gt;</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    ioc      = context.args[0].strip()
    ioc_type = clf.classify(ioc)

    if ioc_type == "unknown":
        await message.reply_text(
            f"❓ Could not classify <code>{ioc}</code> as a known IOC type.\n"
            f"Supported: IP, Domain, URL, MD5, SHA1, SHA256",
            parse_mode=ParseMode.HTML,
        )
        return

    friendly = clf.friendly_type(ioc_type)
    thinking = await message.reply_text(
        f"⏳ Analyzing <code>{ioc}</code> as {friendly}…\n"
        f"<i>Querying all threat intelligence sources…</i>",
        parse_mode=ParseMode.HTML,
    )

    result_dict = {}
    report_text = ""

    try:
        try:
            report_text, result_dict = await _run_analysis(ioc, ioc_type)
        except Exception as e:
            # ── Fallback: cached/local data only ──────────────────────────
            feeds_fb     = []
            watchlist_fb = False
            cached       = None
            try:
                feeds_fb = db.search_feed_entries_by_ioc(ioc)
            except Exception:
                pass
            try:
                watchlist_fb = db.get_watchlist_item(ioc) is not None
            except Exception:
                pass
            try:
                cached = db.get_ioc_enrichment(ioc)
            except Exception:
                pass

            cache_vt = {}
            if cached:
                cache_vt = {
                    "malicious":  cached.get("vt_malicious", 0) or 0,
                    "suspicious": 0,
                    "harmless":   0,
                    "undetected": 0,
                }

            report_text, result_dict = ti_rb.build_ti_report(
                ioc=ioc, ioc_type=ioc_type,
                vt=cache_vt,
                abuse={"abuse_score": cached.get("abuse_score", 0)} if cached else {},
                feeds=feeds_fb,
                in_watchlist=watchlist_fb,
                from_cache=True,
            )
            report_text = (
                f"⚠️ <b>Partial Intelligence Mode</b> — live APIs unavailable\n"
                f"<code>{html_lib.escape(str(e)[:120])}</code>\n\n"
            ) + report_text

    finally:
        try:
            await thinking.delete()
        except Exception:
            pass

    # ── Persist to DB ──────────────────────────────────────────────────────
    db.save_ioc_result(ioc, ioc_type, result_dict)

    enrichment_sources = result_dict.get("soc_sources_active") or []
    tags_list = []
    if result_dict.get("abuse_score", 0) == 100:
        tags_list.append("abuse-100")
    if result_dict.get("otx_pulses", 0) > 0:
        tags_list.append("shared-pulses")
    if result_dict.get("soc_confidence"):
        tags_list.append(f"confidence:{result_dict['soc_confidence']}%")

    db.save_ioc_enrichment(
        ioc=ioc,
        ioc_type=ioc_type,
        risk_score=result_dict.get("threat_score", 0),
        verdict=result_dict.get("risk_level", "Clean"),
        sources=enrichment_sources,
        abuse_score=result_dict.get("abuse_score", 0),
        vt_malicious=result_dict.get("vt_malicious", 0),
        otx_pulses=result_dict.get("otx_pulses", 0),
        country=result_dict.get("country", ""),
        asn=result_dict.get("asn", ""),
        tags=tags_list
    )

    await message.reply_text(
        report_text,
        parse_mode=ParseMode.HTML,
        disable_web_page_preview=True,
    )


async def _run_analysis(ioc: str, ioc_type: str) -> tuple[str, dict]:
    """Dispatch API calls for the given IOC type, then build a Phase 12 TI report."""

    def _safe(res):
        """Convert exceptions to empty dicts; ensure comments are always lists."""
        if isinstance(res, Exception):
            return {}
        if res is None:
            return {}
        return res

    def _safe_list(res):
        """Return res if it's a list, otherwise empty list."""
        if isinstance(res, list):
            return res
        return []

    # ── Local DB context ──────────────────────────────────────────────────
    feeds_from_db: list = []
    in_watchlist:  bool = False
    case_corr:     list = []

    try:
        feeds_from_db = db.search_feed_entries_by_ioc(ioc)
    except Exception:
        pass
    try:
        in_watchlist = db.get_watchlist_item(ioc) is not None
    except Exception:
        pass
    try:
        case_iocs_rows = db.get_case_iocs_by_value(ioc)
        for ci in (case_iocs_rows or []):
            case_corr.append({"case_id": ci.get("case_id", "?")})
    except Exception:
        pass

    # ── IP ─────────────────────────────────────────────────────────────────
    if ioc_type == "ip":
        results = await asyncio.gather(
            api.vt_check_ip(ioc),
            api.abuseipdb_check(ioc),
            api.otx_check_ip(ioc),
            api.geoip_lookup(ioc),
            api.shodan_check_ip(ioc),
            api.greynoise_check_ip(ioc),
            api.rdap_ip(ioc),
            api.vt_comments_ip(ioc),
            return_exceptions=True,
        )
        vt_d, abuse_d, otx_d, geo_d, shodan_d, gn_d, rdap_d, comments_raw = results
        return ti_rb.build_ti_report(
            ioc=ioc, ioc_type=ioc_type,
            vt=_safe(vt_d), abuse=_safe(abuse_d), otx=_safe(otx_d),
            geo=_safe(geo_d), shodan=_safe(shodan_d), greynoise=_safe(gn_d),
            rdap=_safe(rdap_d),
            feeds=feeds_from_db, in_watchlist=in_watchlist,
            case_correlations=case_corr, comments=_safe_list(comments_raw),
        )

    # ── Domain ─────────────────────────────────────────────────────────────
    elif ioc_type == "domain":
        results = await asyncio.gather(
            api.vt_check_domain(ioc),
            api.otx_check_domain(ioc),
            api.dns_resolve_all(ioc),
            api.rdap_domain(ioc),
            api.vt_comments_domain(ioc),
            return_exceptions=True,
        )
        vt_d, otx_d, dns_d, rdap_d, comments_raw = results
        dns_safe = _safe(dns_d) if isinstance(dns_d, dict) and not isinstance(dns_d, Exception) else {}
        return ti_rb.build_ti_report(
            ioc=ioc, ioc_type=ioc_type,
            vt=_safe(vt_d), otx=_safe(otx_d),
            rdap=_safe(rdap_d), dns_records=dns_safe,
            feeds=feeds_from_db, in_watchlist=in_watchlist,
            case_correlations=case_corr, comments=_safe_list(comments_raw),
        )

    # ── Hash ───────────────────────────────────────────────────────────────
    elif ioc_type in ("md5", "sha1", "sha256"):
        results = await asyncio.gather(
            api.vt_check_hash(ioc),
            api.otx_check_hash(ioc),
            api.vt_comments_hash(ioc),
            return_exceptions=True,
        )
        vt_d, otx_d, comments_raw = results
        return ti_rb.build_ti_report(
            ioc=ioc, ioc_type=ioc_type,
            vt=_safe(vt_d), otx=_safe(otx_d),
            feeds=feeds_from_db, in_watchlist=in_watchlist,
            case_correlations=case_corr, comments=_safe_list(comments_raw),
        )

    # ── URL ────────────────────────────────────────────────────────────────
    elif ioc_type == "url":
        results = await asyncio.gather(
            api.vt_check_url(ioc),
            api.otx_check_url(ioc),
            api.vt_comments_url(ioc),
            return_exceptions=True,
        )
        vt_d, otx_d, comments_raw = results

        # Resolve DNS for the URL's domain
        dns_d: dict = {}
        try:
            domain = urlparse(ioc).hostname or ""
            if domain:
                dns_d = await api.dns_resolve_all(domain)
        except Exception:
            pass

        return ti_rb.build_ti_report(
            ioc=ioc, ioc_type=ioc_type,
            vt=_safe(vt_d), otx=_safe(otx_d), dns_records=dns_d,
            feeds=feeds_from_db, in_watchlist=in_watchlist,
            case_correlations=case_corr, comments=_safe_list(comments_raw),
        )

    else:
        raise ValueError(f"Unsupported IOC type: {ioc_type}")
