"""
handlers/email_cmd.py — Email Intelligence Command Handler.

Architecture (Two-Pass Pipeline):
  Pass 1 — Email Intelligence
    • Validate email format
    • Classify provider (public / corporate / disposable)
    • Check MX, SPF, DMARC, DKIM  (via osint_email DNS helpers)
    • Query breach databases       (HIBP + LeakCheck)

  Pass 2 — Domain Intelligence
    • Extract domain from email
    • Run EXACTLY the same pipeline as /check <domain>
      (VT, OTX, DNS, RDAP, feeds, watchlist, case correlations)
    • Build domain TI report via ti_report_builder

  Merge — Render as one Email Intelligence Report:
    [Email Header]
    [Email Validation]
    [Breach Intelligence]
    [Domain Intelligence — full /check report]
    [Raw Evidence Summary]
"""
import re
import logging
import asyncio
import html as _h

from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode

import osint_email as oe
import api_clients as api
import database as db
import ti_report_builder as ti_rb

logger = logging.getLogger(__name__)

SEP = "\u2501" * 26


def _e(v) -> str:
    return _h.escape(str(v or ""))


# ─── Email Validation ───────────────────────────────────────────────────────────

EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')


def _classify_provider(domain: str) -> str:
    d = domain.lower()
    if d in oe.DISPOSABLE_DOMAINS:
        return "\U0001f5d1 Disposable"
    if d in oe.PUBLIC_PROVIDERS:
        return "\U0001f4e7 Public"
    return "\U0001f3e2 Corporate"



# ─── Domain Pipeline (reuses /check engine exactly) ─────────────────────────────

async def _run_domain_check(domain: str) -> tuple[str, dict]:
    """Run the same domain intelligence pipeline as /check <domain>."""
    def _safe(r):
        return r if isinstance(r, dict) and not isinstance(r, Exception) else {}

    def _safe_list(r):
        return r if isinstance(r, list) else []

    # Local DB context
    feeds_from_db: list = []
    in_watchlist:  bool = False
    case_corr:     list = []
    try:
        feeds_from_db = db.search_feed_entries_by_ioc(domain)
    except Exception:
        pass
    try:
        in_watchlist = db.get_watchlist_item(domain) is not None
    except Exception:
        pass
    try:
        rows = db.get_case_iocs_by_value(domain)
        for ci in (rows or []):
            case_corr.append({"case_id": ci.get("case_id", "?")})
    except Exception:
        pass

    # Exact same API calls as check.py for domains
    results = await asyncio.gather(
        api.vt_check_domain(domain),
        api.otx_check_domain(domain),
        api.dns_resolve_all(domain),
        api.rdap_domain(domain),
        api.vt_comments_domain(domain),
        return_exceptions=True,
    )
    vt_d, otx_d, dns_d, rdap_d, comments_raw = results
    dns_safe = _safe(dns_d) if isinstance(dns_d, dict) else {}

    return ti_rb.build_ti_report(
        ioc=domain, ioc_type="domain",
        vt=_safe(vt_d), otx=_safe(otx_d),
        rdap=_safe(rdap_d), dns_records=dns_safe,
        feeds=feeds_from_db, in_watchlist=in_watchlist,
        case_correlations=case_corr, comments=_safe_list(comments_raw),
    )


# ─── Email Intelligence Renderer ────────────────────────────────────────────────

def _render_email_header(email: str, domain: str, provider: str) -> str:
    """Top header block for the Email Intelligence Report."""
    return (
        f"\U0001f4e7 <b>EMAIL INTELLIGENCE REPORT</b>\n"
        f"<code>{SEP}</code>\n"
        f"<b>Email</b>       <code>{_e(email)}</code>\n"
        f"<b>Domain</b>      <code>{_e(domain)}</code>\n"
        f"<code>{SEP}</code>\n\n"
    )


def _render_email_risk_summary(
    mx_records: list, provider: str, domain_verdict: str,
) -> str:
    """Displays a high-level 3-second overview of email/domain posture."""
    mx_ok = bool(mx_records)
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
        
    return (
        f"<code>{SEP}</code>\n"
        f"📊 <b>EMAIL RISK SUMMARY</b>\n"
        f"<code>{SEP}</code>\n"
        f"<b>Status</b>             <code>{status_str}</code>\n"
        f"<b>Provider</b>           {provider}\n"
        f"<b>Domain Reputation</b>   {risk_em} <b>{risk_lbl}</b>\n\n"
    )


def _render_email_validation(
    email: str, domain: str, provider: str,
    mx_records: list, spf: str, dmarc: str, dkim_list: list,
    catch_all: str,
) -> str:
    """Email Validation + DNS security posture section."""
    is_disp   = "Disposable" in provider

    # Catch-all normalization
    ca_raw = str(catch_all).strip().upper()
    if ca_raw.startswith("NO"):
        catch_all_display = "No"
    elif ca_raw.startswith("YES"):
        catch_all_display = "Yes"
    else:
        catch_all_display = "Unknown"

    # SPF rendering
    if spf == "None" or not spf:
        spf_line = "\u274c Missing"
    elif "v=spf1" in spf:
        spf_line = f"\u2705 Active  <code>({_e(spf[:35])}...)</code>"
    else:
        spf_line = f"<code>({_e(spf[:35])}...)</code>"

    # DMARC rendering
    if dmarc == "None" or not dmarc:
        dmarc_line = "\u274c Missing"
    else:
        import re as _re
        pm = _re.search(r'p=(\w+)', dmarc)
        policy = pm.group(1).lower() if pm else "active"
        em_p = "\u2705" if policy in ("reject", "quarantine") else "⚠️"
        dmarc_line = f"{em_p} Policy: <code>{_e(policy)}</code>"

    # DKIM rendering
    if dkim_list:
        dkim_line = "\u2705 Active"
    else:
        dkim_line = "Not Detected"

    # MX listing/missing check
    if mx_records:
        mx_lines = "\n".join(f"  <code>{_e(mx[:70])}</code>" for mx in mx_records[:4])
        mx_block = f"<b>MX Records</b>\n{mx_lines}"
    else:
        mx_block = "<b>MX</b>               <code>Missing</code>"

    return (
        f"<code>{SEP}</code>\n"
        f"\u2709 <b>EMAIL VALIDATION</b>\n"
        f"<code>{SEP}</code>\n"
        f"{mx_block}\n"
        f"<b>SPF Record</b>     {spf_line}\n"
        f"<b>DMARC Policy</b>   {dmarc_line}\n"
        f"<b>DKIM</b>           {dkim_line}\n"
        f"<b>Catch-All</b>      <code>{catch_all_display}</code>\n"
        f"<b>Disposable</b>     {'⚠️ Yes' if is_disp else '✅ No'}\n\n"
    )


def _render_breach_block(hibp: dict, lc: dict) -> str:
    """Breach Intelligence section — merges HIBP + LeakCheck results."""
    # Merge breaches by name (dedup)
    breach_map: dict[str, dict] = {}

    for b in hibp.get("breaches", []):
        name = str(b.get("Name") or "Unknown")
        breach_map[name.lower()] = {
            "name": name,
            "date": str(b.get("BreachDate") or "Unknown"),
        }
    for b in lc.get("breaches", []):
        name = str(b.get("Name") or "Unknown")
        if name.lower() not in breach_map:
            breach_map[name.lower()] = {
                "name": name,
                "date": str(b.get("Date") or "Unknown"),
            }

    all_breaches = list(breach_map.values())
    total = len(all_breaches)

    if total == 0:
        return (
            f"<code>{SEP}</code>\n"
            f"\U0001f525 <b>BREACH INTELLIGENCE</b>\n"
            f"<code>{SEP}</code>\n"
            f"🟢 No public breaches found\n\n"
        )

    return (
        f"<code>{SEP}</code>\n"
        f"\U0001f525 <b>BREACH INTELLIGENCE</b>\n"
        f"<code>{SEP}</code>\n"
        f"🔴 Found in {total} public breaches\n\n"
    )



def _render_domain_separator(domain: str) -> str:
    """Divider between email section and domain TI report."""
    return (
        f"<code>{SEP}</code>\n"
        f"\U0001f310 <b>DOMAIN INTELLIGENCE</b>  —  <code>{_e(domain)}</code>\n"
        f"<code>{SEP}</code>\n\n"
    )


# ─── Main Command Handler ────────────────────────────────────────────────────────

async def email_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/email <address> — Two-pass Email + Domain Intelligence pipeline."""
    message = update.effective_message

    if not context.args:
        await message.reply_text(
            "⚠️ Usage: <code>/email &lt;email_address&gt;</code>\n\n"
            "Example: <code>/email admin@microsoft.com</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    email = context.args[0].strip().lower()

    # ── Step 0: Validate format ──────────────────────────────────────────────
    if not EMAIL_RE.match(email):
        await message.reply_text(
            f"❌ <b>Invalid email format:</b> <code>{_e(email)}</code>\n"
            "Expected format: <code>user@domain.com</code>",
            parse_mode=ParseMode.HTML,
        )
        return

    local_part, domain = email.split("@", 1)
    provider = _classify_provider(domain)

    # ── Thinking indicator ───────────────────────────────────────────────────
    thinking = await message.reply_text(
        f"⏳ <b>Email Intelligence</b>  <code>{_e(email)}</code>\n"
        f"<i>Pass 1: Validating email, checking breach databases…</i>",
        parse_mode=ParseMode.HTML,
    )

    async def _progress(text: str):
        try:
            await thinking.edit_text(
                f"⏳ <b>Email Intelligence</b>  <code>{_e(email)}</code>\n"
                f"<i>{_e(text)}</i>",
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass

    try:
        # ── PASS 1: Email-specific data ──────────────────────────────────────
        await _progress("Pass 1: Querying DNS (MX, SPF, DMARC, DKIM)…")

        (spf, dmarc), mx_records, dkim_list, hibp_res, lc_res = await asyncio.gather(
            asyncio.to_thread(oe.check_spf_dmarc, domain),
            asyncio.to_thread(oe.check_mx_records, domain),
            asyncio.to_thread(oe.check_dkim_records, domain),
            oe.check_hibp_breaches(email),
            oe.check_leakcheck(email),
            return_exceptions=False,
        )

        # SMTP catch-all (quick, non-blocking)
        primary_mx = mx_records[0].split()[0] if mx_records else ""
        try:
            catch_all = await asyncio.to_thread(oe.smtp_catch_all_check, domain, primary_mx)
        except Exception:
            catch_all = "Unknown"

        # ── PASS 2: Domain Intelligence (same as /check <domain>) ────────────
        await _progress(f"Pass 2: Running domain intelligence on {domain}…")

        domain_msg, domain_meta = await _run_domain_check(domain)

        # ── Assemble the report ──────────────────────────────────────────────
        await thinking.delete()

        email_header     = _render_email_header(email, domain, provider)
        domain_verdict   = domain_meta.get("risk_level") or domain_meta.get("soc_verdict") or "Clean"
        email_risk_summary = _render_email_risk_summary(
            mx_records, provider, domain_verdict
        )
        email_validation = _render_email_validation(
            email, domain, provider,
            mx_records, spf, dmarc, dkim_list, catch_all,
        )
        breach_block     = _render_breach_block(hibp_res, lc_res)
        domain_sep       = _render_domain_separator(domain)

        # Chunk into ≤4000-char Telegram messages
        parts = [email_header + email_risk_summary + email_validation, breach_block]

        # Domain TI report may already be multi-message (split by ti_report_builder)
        # We prepend the separator to the domain_msg
        domain_full = domain_sep + domain_msg
        parts.append(domain_full)



        final_messages: list[str] = []
        for p in parts:
            if len(p) > 3900:
                # Split at nearest newline before 3900
                while len(p) > 3900:
                    split_at = p.rfind("\n", 0, 3900)
                    if split_at < 100:
                        split_at = 3900
                    final_messages.append(p[:split_at])
                    p = p[split_at:].lstrip("\n")
                if p.strip():
                    final_messages.append(p)
            else:
                final_messages.append(p)

        for idx, msg_text in enumerate(final_messages):
            is_last = (idx == len(final_messages) - 1)
            await message.reply_text(
                msg_text,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
            )

    except Exception as exc:
        logger.error(f"Email intelligence failed for {email}: {exc}", exc_info=True)
        try:
            await thinking.delete()
        except Exception:
            pass
        await message.reply_text(
            f"❌ <b>Analysis Failed:</b> <code>{_e(str(exc)[:120])}</code>",
            parse_mode=ParseMode.HTML,
        )


# ─── SMTP Header Forensic Parser (kept from original) ───────────────────────────

def parse_raw_headers(header_text: str) -> dict:
    """Parse SMTP headers, unfold lines, and extract routing hops."""
    import re as _re
    unfolded_lines = []
    for line in header_text.splitlines():
        if not line:
            continue
        if line.startswith((' ', '\t')) and unfolded_lines:
            unfolded_lines[-1] += " " + line.strip()
        else:
            unfolded_lines.append(line.strip())

    headers = {}
    received_headers = []
    for line in unfolded_lines:
        if ':' in line:
            key, val = line.split(':', 1)
            key = key.strip().lower()
            val = val.strip()
            if key == "received":
                received_headers.append(val)
            else:
                headers[key] = val

    ip_chain = []
    for rec in received_headers:
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', rec)
        for ip in ips:
            octets = ip.split('.')
            if all(0 <= int(o) <= 255 for o in octets) and ip not in ('127.0.0.1',):
                ip_chain.append(ip)
    ip_chain = list(dict.fromkeys(ip_chain))
    originating_ip = ip_chain[-1] if ip_chain else None

    auth_results = headers.get("authentication-results", "")
    spf_result = dkim_result = dmarc_result = "Unknown"
    if auth_results:
        m = re.search(r'spf=(\w+)', auth_results)
        if m: spf_result = m.group(1)
        m = re.search(r'dkim=(\w+)', auth_results)
        if m: dkim_result = m.group(1)
        m = re.search(r'dmarc=(\w+)', auth_results)
        if m: dmarc_result = m.group(1)
    rec_spf = headers.get("received-spf", "")
    if rec_spf and spf_result == "Unknown":
        parts = rec_spf.split()
        if parts:
            spf_result = parts[0]

    return {
        "from":          headers.get("from", "Unknown"),
        "to":            headers.get("to", "Unknown"),
        "subject":       headers.get("subject", "Unknown"),
        "date":          headers.get("date", "Unknown"),
        "received_hops": len(received_headers),
        "ip_chain":      ip_chain,
        "originating_ip": originating_ip,
        "spf":           spf_result,
        "dkim":          dkim_result,
        "dmarc":         dmarc_result,
    }


async def header_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/header <text> — Parses raw SMTP headers for forensic path tracing."""
    message = update.effective_message

    header_text = ""
    if context.args:
        header_text = " ".join(context.args).strip()
    elif message.reply_to_message and message.reply_to_message.text:
        header_text = message.reply_to_message.text.strip()

    if not header_text or len(header_text) < 30:
        await message.reply_text(
            "⚠️ Usage: Send <code>/header &lt;pasted headers&gt;</code>, "
            "or reply <code>/header</code> to a message containing raw headers.",
            parse_mode=ParseMode.HTML,
        )
        return

    thinking = await message.reply_text(
        "⏳ Forensically parsing SMTP header routing…",
        parse_mode=ParseMode.HTML,
    )

    try:
        info = parse_raw_headers(header_text)

        orig_ip      = info["originating_ip"]
        orig_details = "N/A"
        spf_ip_status = "N/A"

        if orig_ip:
            geo = await api.geoip_lookup(orig_ip)
            if "error" not in geo:
                orig_details = f"\U0001f4cd {_e(geo.get('country', ''))} / {_e(geo.get('city', ''))} ({_e(geo.get('asn', ''))})"
            else:
                orig_details = "Lookup failed"
            vt_ip = await api.vt_check_ip(orig_ip)
            mal   = int(vt_ip.get("malicious", 0) or 0) if "error" not in vt_ip else 0
            spf_ip_status = f"\U0001f534 Malicious ({mal} VT detections)" if mal > 0 else "\U0001f7e2 Benign (no VT matches)"

        # Warnings
        warnings = []
        if info["spf"] in ("fail", "softfail"):
            warnings.append(f"SPF <b>FAILED</b> ({info['spf']})")
        if info["dmarc"] in ("fail", "reject"):
            warnings.append("DMARC <b>FAILED</b>")
        warn_block = ""
        if warnings:
            warn_block = "<b>\U0001f6a8 Spoofing Warnings:</b>\n" + "\n".join(f"  \u2022 {w}" for w in warnings) + "\n\n"

        report = (
            f"\u2709\ufe0f <b>EMAIL HEADER FORENSIC REPORT</b>\n"
            f"<code>{SEP}</code>\n"
            f"<b>From:</b>     <code>{_e(info['from'])}</code>\n"
            f"<b>Subject:</b>  <code>{_e(info['subject'])}</code>\n"
            f"<b>Date:</b>     <code>{_e(info['date'])}</code>\n\n"
            f"<b>SPF:</b>      <code>{_e(info['spf'].upper())}</code>\n"
            f"<b>DKIM:</b>     <code>{_e(info['dkim'].upper())}</code>\n"
            f"<b>DMARC:</b>    <code>{_e(info['dmarc'].upper())}</code>\n\n"
            f"<b>Originating IP:</b>  <code>{_e(orig_ip or 'Not found')}</code>\n"
            f"<b>Location / ISP:</b>  {orig_details}\n"
            f"<b>IP Reputation:</b>   {spf_ip_status}\n"
            f"<b>Total Hops:</b>      <code>{info['received_hops']}</code>\n\n"
            f"{warn_block}"
            f"<i>SMTP Transit Route Forensic Parse</i>"
        )

        await thinking.delete()
        await message.reply_text(report, parse_mode=ParseMode.HTML)

    except Exception as e:
        logger.error(f"Header parse error: {e}", exc_info=True)
        try:
            await thinking.delete()
        except Exception:
            pass
        await message.reply_text(
            f"❌ <b>Forensic Parsing Failed:</b> <code>{_e(str(e)[:100])}</code>",
            parse_mode=ParseMode.HTML,
        )
