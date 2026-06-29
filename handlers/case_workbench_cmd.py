"""
handlers/case_workbench_cmd.py - Analyst Workbench Command Handlers

Commands:
  /newcase <title>   - Start a new named investigation case
  /case [case_id]    - Switch active case, or view active case dashboard
  /cases             - List all cases in the database
  /note <type> <target_id> <text> - Add analyst notes, bookmarks, verdicts, overrides
  /mode <mode>       - Change output report format mode
  /graph             - Show a text representation of the evidence correlation graph
"""
from __future__ import annotations

import logging
from telegram import Update
from telegram.ext import ContextTypes
from telegram.constants import ParseMode
import database as db
import case_engine
import html as _h

logger = logging.getLogger(__name__)

# ─── Helper: HTML Escape ──────────────────────────────────────────────────────
def escape(text: str) -> str:
    return _h.escape(str(text))

# ─── /newcase Command ─────────────────────────────────────────────────────────
async def newcase_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.effective_message
    chat_id = update.effective_chat.id
    
    title = " ".join(context.args).strip()
    if not title:
        title = f"Manual Investigation Case"

    case_id = case_engine.create_new_named_case(chat_id, title)
    
    await message.reply_text(
        f"📂 <b>NEW INVESTIGATION CASE STARTED</b>\n"
        f"<code>━━━━━━━━━━━━━━━━━━━━━━━━━━</code>\n"
        f"🔬 <b>Case ID:</b>  <code>{case_id}</code>\n"
        f"🏷 <b>Title:</b>    <code>{escape(title)}</code>\n"
        f"📊 <b>Status:</b>   <code>ACTIVE</code>\n\n"
        f"<i>Every uploaded artifact will now automatically become part of this active investigation.</i>",
        parse_mode=ParseMode.HTML
    )

# ─── /case Command ────────────────────────────────────────────────────────────
async def case_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.effective_message
    chat_id = update.effective_chat.id

    arg = " ".join(context.args).strip()
    if arg:
        # User is trying to switch to a specific case
        success = case_engine.switch_active_case(chat_id, arg)
        if success:
            await message.reply_text(
                f"✅ Active case switched to: <code>{arg}</code>",
                parse_mode=ParseMode.HTML
            )
        else:
            await message.reply_text(
                f"❌ Case <code>{escape(arg)}</code> not found in database.",
                parse_mode=ParseMode.HTML
            )
            return

    # Show dashboard of active case
    case_id = case_engine.resolve_active_case(chat_id)
    dash = case_engine.generate_case_dashboard(case_id)
    
    mode = case_engine.get_chat_mode(chat_id)
    report_pages = case_engine.format_case_report(case_id, mode)
    
    for page in report_pages:
        if page.strip():
            await message.reply_text(
                page,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True
            )

# ─── /cases Command ───────────────────────────────────────────────────────────
async def cases_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.effective_message
    chat_id = update.effective_chat.id

    cases = db.get_all_cases()
    if not cases:
        await message.reply_text("📁 No cases found in the database. Use `/newcase` to start one.")
        return

    active_id = db.get_active_case_id(chat_id)
    
    msg = (
        f"📁 <b>INVESTIGATION CASES LIST</b>\n"
        f"<code>━━━━━━━━━━━━━━━━━━━━━━━━━━</code>\n\n"
    )
    for i, c in enumerate(cases[:10], 1):
        status_tag = "🟢 ACTIVE" if c["status"] == "ACTIVE" else "⚪ CLOSED"
        active_tag = "⭐️ " if c["case_id"] == active_id else ""
        msg += (
            f"<b>{i}. {active_tag}{c['title']}</b>\n"
            f"   ID: <code>{c['case_id']}</code> | Verdict: <code>{c['manual_verdict']}</code>\n"
            f"   Status: {status_tag} | Created: <i>{c['created_at'][:10]}</i>\n\n"
        )
    await message.reply_text(msg, parse_mode=ParseMode.HTML)

# ─── /note Command ────────────────────────────────────────────────────────────
async def note_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Allow analysts to attach notes, overrides, bookmarks, and verdicts to findings.
    Usage:
      /note case <verdict>             - Set manual verdict for active case (BENIGN, SUSPICIOUS, MALICIOUS, FALSE_POSITIVE)
      /note ioc <ioc_value> <note>     - Set note on an IOC
      /note bookmark <finding_title>   - Bookmark/unbookmark a finding
      /note override <finding_title> <severity> - Override finding severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
      /note info <finding_title> <note> - Add analyst note to a finding
    """
    message = update.effective_message
    chat_id = update.effective_chat.id
    case_id = case_engine.resolve_active_case(chat_id)

    args = context.args
    if not args or len(args) < 2:
        await message.reply_text(
            f"📝 <b>Analyst Note Workbench</b>\n"
            f"<code>━━━━━━━━━━━━━━━━━━━━━━━━━━</code>\n"
            f"Attach findings comments, overrides, and verdicts to the active case.\n\n"
            f"<b>Usage:</b>\n"
            f"  • <code>/note case &lt;verdict&gt;</code>\n"
            f"    <i>Set case verdict (BENIGN | SUSPICIOUS | MALICIOUS | FALSE_POSITIVE)</i>\n\n"
            f"  • <code>/note ioc &lt;ioc_value&gt; &lt;note text&gt;</code>\n"
            f"    <i>Add note to a specific case-wide IOC</i>\n\n"
            f"  • <code>/note bookmark &lt;finding_title&gt;</code>\n"
            f"    <i>Toggle bookmark on a finding (displays on dashboard)</i>\n\n"
            f"  • <code>/note override &lt;finding_title&gt; &lt;severity&gt;</code>\n"
            f"    <i>Override finding severity (CRITICAL | HIGH | MEDIUM | LOW)</i>\n\n"
            f"  • <code>/note info &lt;finding_title&gt; &lt;comment&gt;</code>\n"
            f"    <i>Add notes/comments to a specific finding</i>",
            parse_mode=ParseMode.HTML
        )
        return

    subcmd = args[0].lower()
    target = args[1]
    
    if subcmd == "case":
        verdict = target.upper()
        if verdict not in ("BENIGN", "SUSPICIOUS", "MALICIOUS", "FALSE_POSITIVE", "CONFIRMED THREAT"):
            await message.reply_text("❌ Invalid verdict. Choose: BENIGN | SUSPICIOUS | MALICIOUS | FALSE_POSITIVE | CONFIRMED THREAT")
            return
        db.save_analyst_note(case_id, "case", case_id, manual_verdict=verdict)
        db.update_case_verdict(case_id, verdict)
        await message.reply_text(f"✅ Verdict for case <code>{case_id}</code> set to: <b>{verdict}</b>", parse_mode=ParseMode.HTML)
        case_engine.recorrelate_case(case_id) # recalculate risk/verdict details
        return

    elif subcmd == "ioc":
        note_text = " ".join(args[2:]).strip()
        if not note_text:
            await message.reply_text("❌ Please provide note text. Usage: `/note ioc <ioc_value> <note text>`")
            return
        db.save_analyst_note(case_id, "ioc", target, note_text=note_text)
        await message.reply_text(f"✅ Note added to IOC <code>{escape(target)}</code>", parse_mode=ParseMode.HTML)
        case_engine.recorrelate_case(case_id)
        return

    elif subcmd == "bookmark":
        finding_title = " ".join(args[1:]).strip()
        existing = db.get_analyst_note(case_id, "finding", finding_title)
        
        new_val = 1
        if existing and existing.get("bookmark") == 1:
            new_val = 0
            
        db.save_analyst_note(case_id, "finding", finding_title, bookmark=new_val)
        status_txt = "bookmarked (prioritized on dashboard)" if new_val == 1 else "unbookmarked"
        await message.reply_text(f"✅ Finding <i>'{escape(finding_title)}'</i> is now {status_txt}.", parse_mode=ParseMode.HTML)
        case_engine.recorrelate_case(case_id)
        return

    elif subcmd == "override":
        if len(args) < 3:
            await message.reply_text("❌ Usage: `/note override <finding_title> <severity>`")
            return
        severity = args[-1].upper()
        finding_title = " ".join(args[1:-1]).strip()
        
        if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            await message.reply_text("❌ Severity must be: CRITICAL | HIGH | MEDIUM | LOW | INFO")
            return
            
        db.save_analyst_note(case_id, "finding", finding_title, severity_override=severity)
        await message.reply_text(f"✅ Severity of <i>'{escape(finding_title)}'</i> overridden to: <b>{severity}</b>", parse_mode=ParseMode.HTML)
        case_engine.recorrelate_case(case_id)
        return

    elif subcmd == "info":
        note_text = " ".join(args[2:]).strip()
        if not note_text:
            await message.reply_text("❌ Please provide comments. Usage: `/note info <finding_title> <comment>`")
            return
        db.save_analyst_note(case_id, "finding", target, note_text=note_text)
        await message.reply_text(f"✅ Analyst comment attached to finding <i>'{escape(target)}'</i>", parse_mode=ParseMode.HTML)
        case_engine.recorrelate_case(case_id)
        return

    else:
        await message.reply_text("❌ Unknown subcmd. Choose: case | ioc | bookmark | override | info")

# ─── /mode Command ────────────────────────────────────────────────────────────
async def mode_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.effective_message
    chat_id = update.effective_chat.id

    args = context.args
    if not args:
        current = case_engine.get_chat_mode(chat_id)
        await message.reply_text(
            f"📊 <b>Investigation Output Modes</b>\n"
            f"<code>━━━━━━━━━━━━━━━━━━━━━━━━━━</code>\n"
            f"Current chat default mode: <code>{current.upper()}</code>\n\n"
            f"<b>Change default mode:</b>\n"
            f"  • <code>/mode executive</code> (1 page, high-level summary)\n"
            f"  • <code>/mode soc</code> (actionable alerts & MITRE techniques)\n"
            f"  • <code>/mode dfir</code> (deep-dive metadata & forensics timeline)\n"
            f"  • <code>/mode hunt</code> (pivots & correlation links)\n"
            f"  • <code>/mode full</code> (complete technical compilation)",
            parse_mode=ParseMode.HTML
        )
        return

    mode = args[0].lower()
    if mode not in ("executive", "soc", "dfir", "hunt", "full"):
        await message.reply_text("❌ Invalid mode. Choose: executive | soc | dfir | hunt | full")
        return

    case_engine.set_chat_mode(chat_id, mode)
    await message.reply_text(f"✅ Default report output mode for this chat set to: <b>{mode.upper()}</b>", parse_mode=ParseMode.HTML)

# ─── /graph Command ───────────────────────────────────────────────────────────
async def graph_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.effective_message
    chat_id = update.effective_chat.id
    case_id = case_engine.resolve_active_case(chat_id)

    nodes, edges = db.get_case_graph(case_id)
    if not nodes:
        await message.reply_text("⚠️ No correlation graph found. Upload evidence artifacts first.")
        return

    sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
    msg = (
        f"🔗 <b>INVESTIGATION CORRELATION GRAPH</b>\n"
        f"<code>{sep}</code>\n"
        f"Case ID: <code>{case_id}</code>\n"
        f"Nodes: <code>{len(nodes)}</code> | Edges: <code>{len(edges)}</code>\n"
        f"<code>{sep}</code>\n\n"
    )

    # Group nodes by type
    nodes_by_type = {}
    for n in nodes:
        nodes_by_type[n["node_type"]] = nodes_by_type.get(n["node_type"], []) + [n["node_id"]]

    msg += "<b>📂 Nodes:</b>\n"
    for ntype, ids in nodes_by_type.items():
        msg += f"  • <b>{ntype}:</b> {', '.join(f'<code>{escape(nid[:20])}</code>' for nid in ids[:6])}"
        if len(ids) > 6:
            msg += f" <i>(and {len(ids)-6} more)</i>"
        msg += "\n"

    msg += "\n<b>🔄 Correlation Pivot Relationships:</b>\n"
    correlated_edges = [e for e in edges if e["rel_type"].startswith("CORRELATED_")]
    
    if correlated_edges:
        for e in correlated_edges[:15]:
            msg += f"  • <code>{escape(e['source_node'][:20])}</code> ⟷ [<b>{e['rel_type'].replace('CORRELATED_', '')}</b>] ⟷ <code>{escape(e['target_node'][:20])}</code>\n"
    else:
        # Fallback list APPEARS_IN relationships
        appears_edges = [e for e in edges if e["rel_type"] == "APPEARS_IN"]
        for e in appears_edges[:10]:
            msg += f"  • <code>{escape(e['source_node'][:20])}</code> ➜ [<b>APPEARS_IN</b>] ➜ <code>{escape(e['target_node'][:20])}</code>\n"
            
    await message.reply_text(msg, parse_mode=ParseMode.HTML)
