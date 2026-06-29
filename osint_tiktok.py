"""
osint_tiktok.py - TikTok Social Media Intelligence Engine

Strategy (multi-tier fallback):
  Tier 1: Parse __UNIVERSAL_DATA_FOR_REHYDRATION__ JSON from tiktok.com/@username HTML
  Tier 2: Regex extraction of key data fields from HTML body
  Tier 3: Open Graph meta tags extraction (minimal data)

Returns structured TikTokProfile with all available public data.
"""
import asyncio
import re
import json
import html as html_lib
from typing import Optional
import httpx


# ─── Browser-realistic headers ────────────────────────────────────────────────

_CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

_TIKTOK_HEADERS = {
    "User-Agent":      _CHROME_UA,
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-Fetch-Dest":  "document",
    "Sec-Fetch-Mode":  "navigate",
    "Sec-Fetch-Site":  "none",
    "Upgrade-Insecure-Requests": "1",
}


# ─── Empty profile factory ────────────────────────────────────────────────────

def _empty_profile(username: str) -> dict:
    return {
        "username":        username,
        "display_name":    "",
        "bio":             "",
        "profile_pic_url": "",
        "bio_link":        "",
        "followers":       None,
        "following":       None,
        "likes":           None,
        "video_count":     None,
        "digg_count":      None,     # videos user liked
        "is_verified":     False,
        "is_private":      False,
        "user_id":         "",
        "found":           False,
        "data_tier":       "",
        "error":           "",
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  Tier 1 — __UNIVERSAL_DATA_FOR_REHYDRATION__ JSON extraction
# ═══════════════════════════════════════════════════════════════════════════════

async def _fetch_tiktok_page(username: str, client: httpx.AsyncClient) -> Optional[str]:
    """Fetch TikTok profile page HTML."""
    username = username.lstrip("@")
    url = f"https://www.tiktok.com/@{username}"
    try:
        r = await client.get(url, headers=_TIKTOK_HEADERS, timeout=20)
        if r.status_code == 404:
            return "404"
        if r.status_code != 200:
            return None
        return r.text
    except Exception:
        return None


def _parse_universal_data(html: str, username: str) -> Optional[dict]:
    """Extract data from __UNIVERSAL_DATA_FOR_REHYDRATION__ script tag."""
    # Find the script tag with this ID
    match = re.search(
        r'<script\s+id=["\']__UNIVERSAL_DATA_FOR_REHYDRATION__["\'][^>]*>(.*?)</script>',
        html, re.DOTALL
    )
    if not match:
        # Also try the data embedded without id attribute
        match = re.search(
            r'__UNIVERSAL_DATA_FOR_REHYDRATION__[^{]*(\{.{20,}\})',
            html, re.DOTALL
        )
    if not match:
        return None

    try:
        data = json.loads(match.group(1))
    except Exception:
        return None

    # Navigate to user detail
    default_scope = data.get("__DEFAULT_SCOPE__", {})
    user_detail   = default_scope.get("webapp.user-detail", {})
    user_info     = user_detail.get("userInfo", {})

    if not user_info:
        return None

    user  = user_info.get("user", {})
    stats = user_info.get("stats", {})

    if not user:
        return None

    p = _empty_profile(username)
    p["username"]        = user.get("uniqueId", username)
    p["display_name"]    = user.get("nickname", "") or ""
    p["bio"]             = user.get("signature", "") or ""
    p["profile_pic_url"] = user.get("avatarLarger") or user.get("avatarMedium") or user.get("avatarThumb", "") or ""
    p["user_id"]         = str(user.get("id", ""))
    p["is_verified"]     = bool(user.get("verified", False))
    p["is_private"]      = bool(user.get("privateAccount", False))

    # Bio link
    bio_link = user.get("bioLink", {})
    if isinstance(bio_link, dict):
        p["bio_link"] = bio_link.get("link", "") or ""
    elif isinstance(bio_link, str):
        p["bio_link"] = bio_link

    # Stats
    p["followers"]   = stats.get("followerCount")
    p["following"]   = stats.get("followingCount")
    p["likes"]       = stats.get("heartCount") or stats.get("diggCount")
    p["video_count"] = stats.get("videoCount")
    p["digg_count"]  = stats.get("diggCount")

    p["found"]     = True
    p["data_tier"] = "Universal Data JSON (Tier 1)"
    return p


# ═══════════════════════════════════════════════════════════════════════════════
#  Tier 2 — Regex extraction from raw HTML body
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_html_regex(html: str, username: str) -> Optional[dict]:
    """Extract TikTok profile fields via targeted regex from HTML body."""
    p = _empty_profile(username)
    p["data_tier"] = "HTML Regex (Tier 2)"

    # Try to find any embedded JSON object with user data
    # Pattern: "uniqueId":"username" nearby data
    for pattern, key in [
        (r'"uniqueId"\s*:\s*"([^"]+)"',     "username"),
        (r'"nickname"\s*:\s*"([^"]+)"',     "display_name"),
        (r'"signature"\s*:\s*"([^"]*)"',    "bio"),
        (r'"followerCount"\s*:\s*(\d+)',    "followers"),
        (r'"followingCount"\s*:\s*(\d+)',   "following"),
        (r'"heartCount"\s*:\s*(\d+)',       "likes"),
        (r'"videoCount"\s*:\s*(\d+)',       "video_count"),
        (r'"verified"\s*:\s*(true|false)',  "is_verified"),
        (r'"privateAccount"\s*:\s*(true|false)', "is_private"),
        (r'"avatarLarger"\s*:\s*"([^"]+)"', "profile_pic_url"),
    ]:
        m = re.search(pattern, html)
        if m:
            val = m.group(1)
            if key in ("followers", "following", "likes", "video_count"):
                try:
                    p[key] = int(val)
                except ValueError:
                    pass
            elif key in ("is_verified", "is_private"):
                p[key] = (val == "true")
            else:
                p[key] = html_lib.unescape(val)

    if p.get("username") or p.get("followers") is not None:
        p["found"] = True
    return p


# ═══════════════════════════════════════════════════════════════════════════════
#  Tier 3 — Open Graph meta tags
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_og_meta(html: str, username: str) -> dict:
    """Extract minimal profile data from Open Graph meta tags."""
    p = _empty_profile(username)
    p["data_tier"] = "Open Graph (Tier 3)"

    og_title = re.search(r'<meta\s+property="og:title"\s+content="([^"]*)"', html)
    og_desc  = re.search(r'<meta\s+property="og:description"\s+content="([^"]*)"', html)
    og_image = re.search(r'<meta\s+property="og:image"\s+content="([^"]*)"', html)
    tw_desc  = re.search(r'<meta\s+name="description"\s+content="([^"]*)"', html)

    if og_title:
        raw = html_lib.unescape(og_title.group(1))
        # e.g. "TikTok – Make Your Day" or "@username on TikTok"
        name_m = re.match(r'([^(@]+)\s*[\(@]', raw)
        if name_m:
            p["display_name"] = name_m.group(1).strip()

    if og_desc or tw_desc:
        raw = html_lib.unescape((og_desc or tw_desc).group(1))
        # Extract follower/like counts from description
        follower_m = re.search(r'([\d,\.]+[KMkBbMm]?)\s*(?:Followers|followers|fans)', raw)
        like_m     = re.search(r'([\d,\.]+[KMkBbMm]?)\s*(?:Likes|likes|Hearts|hearts)', raw)
        if follower_m:
            p["followers"] = _parse_count_str(follower_m.group(1))
        if like_m:
            p["likes"] = _parse_count_str(like_m.group(1))
        p["bio"] = raw[:200]

    if og_image:
        p["profile_pic_url"] = og_image.group(1)

    # At least check for existence
    if f"@{username}" in html or f'"uniqueId":"{username}"' in html:
        p["found"] = True

    return p


def _parse_count_str(s: str) -> Optional[int]:
    s = s.strip().replace(",", "")
    try:
        sl = s.lower()
        if sl.endswith("k"):
            return int(float(sl[:-1]) * 1_000)
        if sl.endswith("m"):
            return int(float(sl[:-1]) * 1_000_000)
        if sl.endswith("b"):
            return int(float(sl[:-1]) * 1_000_000_000)
        return int(float(s))
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
#  Risk & Engagement Analysis
# ═══════════════════════════════════════════════════════════════════════════════

_SUSPICIOUS_KEYWORDS = [
    "official", "real", "verified", "original", "giveaway",
    "crypto", "bitcoin", "nft", "investment", "earn", "promo",
    "support", "admin", "customer", "service",
]

def _analyze_tiktok_risk(profile: dict) -> dict:
    username = profile.get("username", "").lower()
    bio      = profile.get("bio", "").lower()
    followers   = profile.get("followers") or 0
    following   = profile.get("following") or 0
    likes       = profile.get("likes") or 0
    video_count = profile.get("video_count") or 0
    is_verified = profile.get("is_verified", False)

    signals    = []
    risk_score = 0

    # Username patterns
    if re.search(r'\d{2,}$', username):
        signals.append("Username ends with digits")
        risk_score += 12

    if len(username) > 24:
        signals.append("Unusually long username")
        risk_score += 8

    for kw in _SUSPICIOUS_KEYWORDS:
        if kw in username or kw in bio:
            signals.append(f"Suspicious keyword detected: '{kw}'")
            risk_score += 20
            break

    # Follower/ratio analysis
    if followers > 0 and following > 0:
        ratio = following / followers
        if ratio > 10 and followers < 500:
            signals.append("High following-to-follower ratio")
            risk_score += 15

    if followers > 100_000 and video_count < 5 and not is_verified:
        signals.append("Very high followers with almost no videos")
        risk_score += 30

    if followers > 50_000 and not is_verified:
        signals.append("Large unverified account")
        risk_score += 10

    # Engagement estimation
    if followers > 0 and likes > 0:
        like_ratio = likes / max(followers, 1)
        if like_ratio > 10:
            engagement = "Very High"
        elif like_ratio > 3:
            engagement = "High"
        elif like_ratio > 0.5:
            engagement = "Medium"
        else:
            engagement = "Low"
    elif video_count and video_count > 50:
        engagement = "Medium"
    else:
        engagement = "Unknown"

    risk_score = min(risk_score, 100)

    if risk_score >= 60:
        imp, em = "High", "🔴"
    elif risk_score >= 35:
        imp, em = "Medium", "🟠"
    elif risk_score >= 15:
        imp, em = "Low", "🟡"
    else:
        imp, em = "Minimal", "🟢"

    # Activity estimation
    if video_count and video_count > 200 and followers and followers > 5000:
        activity = "High"
    elif video_count and video_count > 30:
        activity = "Medium"
    elif video_count and video_count > 0:
        activity = "Low"
    else:
        activity = "Unknown"

    return {
        "risk_score":       risk_score,
        "impersonation":    imp,
        "impersonation_em": em,
        "activity":         activity,
        "engagement":       engagement,
        "signals":          signals[:5],
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  Main Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

async def investigate_tiktok(username: str) -> dict:
    """
    Full TikTok intelligence investigation for a username.
    Returns profile + risk analysis dict.
    """
    username = username.lstrip("@").strip()

    async with httpx.AsyncClient(
        timeout=25,
        follow_redirects=True,
        headers={"User-Agent": _CHROME_UA},
    ) as client:
        html = await _fetch_tiktok_page(username, client)

    if html == "404":
        p = _empty_profile(username)
        p["error"]     = "Profile not found (404)"
        p["data_tier"] = "N/A"
        p["risk"]      = _analyze_tiktok_risk(p)
        return p

    if not html:
        p = _empty_profile(username)
        p["error"]     = "TikTok blocked the request or network error"
        p["data_tier"] = "N/A"
        p["risk"]      = _analyze_tiktok_risk(p)
        return p

    # Tier 1: Universal Data JSON
    profile = _parse_universal_data(html, username)

    # Tier 2: HTML regex
    if not profile or not profile.get("found"):
        profile = _parse_html_regex(html, username)

    # Tier 3: OG meta tags
    if not profile or not profile.get("found"):
        profile = _parse_og_meta(html, username)

    # Merge tiers if we got partial data
    if profile:
        for key in ("followers", "following", "likes", "video_count", "display_name", "bio"):
            if profile.get(key) is None or profile.get(key) == "":
                # Try regex as supplement
                t2 = _parse_html_regex(html, username)
                if t2.get(key) is not None and t2.get(key) != "":
                    profile[key] = t2[key]
                break

    if not profile:
        profile = _empty_profile(username)
        profile["error"] = "All extraction strategies failed"

    profile["risk"] = _analyze_tiktok_risk(profile)
    return profile


# ═══════════════════════════════════════════════════════════════════════════════
#  Report Formatter
# ═══════════════════════════════════════════════════════════════════════════════

def _fmt_count(n: Optional[int]) -> str:
    if n is None:
        return "N/A"
    if n >= 1_000_000:
        return f"{n/1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n/1_000:.1f}K"
    return str(n)


def format_tiktok_report(profile: dict) -> str:
    sep      = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
    h        = html_lib.escape
    username = profile.get("username", "unknown")

    if not profile.get("found"):
        err = profile.get("error", "Unknown error")
        return (
            f"📱 <b>Social Media Intelligence</b>\n"
            f"<code>{sep}</code>\n\n"
            f"🔹 <b>Platform:</b> TikTok\n"
            f"🔹 <b>Target:</b> <code>@{h(username)}</code>\n\n"
            f"❌ <b>Profile not found or data unavailable.</b>\n"
            f"<i>{h(err)}</i>\n\n"
            f"<i>Account may be private, deleted, or the platform is blocking requests.</i>\n"
            f"<code>{sep}</code>"
        )

    risk     = profile.get("risk", {})
    r_em     = risk.get("impersonation_em", "⚪")
    score    = risk.get("risk_score", 0)
    display  = profile.get("display_name", "")
    bio      = profile.get("bio", "")
    bio_link = profile.get("bio_link", "")
    pic_url  = profile.get("profile_pic_url", "")

    verified_str = "✅ Yes" if profile.get("is_verified") else "❌ No"
    private_str  = "🔒 Private" if profile.get("is_private") else "🌐 Public"

    msg = (
        f"📱 <b>Social Media Intelligence Report</b>\n"
        f"<code>{sep}</code>\n\n"
        f"🔹 <b>Platform:</b> TikTok\n"
        f"🔹 <b>Target:</b> <a href=\"https://tiktok.com/@{h(username)}\">@{h(username)}</a>\n"
        f"🔹 <b>Data Source:</b> <i>{profile.get('data_tier', 'Unknown')}</i>\n\n"
    )

    # ── Profile Section ──────────────────────────────────────────────────────
    msg += "<b>👤 PROFILE:</b>\n"
    if display:
        msg += f"  • <b>Display Name:</b> {h(display)}\n"
    if bio:
        msg += f"  • <b>Bio:</b> <i>{h(bio[:180])}</i>\n"
    if bio_link:
        msg += f"  • <b>Link:</b> <a href=\"{h(bio_link)}\">{h(bio_link[:50])}</a>\n"
    if pic_url:
        msg += f"  • <b>Photo:</b> <a href=\"{h(pic_url)}\">View Profile Picture</a>\n"
    if profile.get("user_id"):
        msg += f"  • <b>User ID:</b> <code>{h(profile['user_id'])}</code>\n"
    msg += "\n"

    # ── Metrics Section ──────────────────────────────────────────────────────
    msg += "<b>📊 METRICS:</b>\n"
    msg += f"  • <b>Followers:</b> {_fmt_count(profile.get('followers'))}\n"
    msg += f"  • <b>Following:</b> {_fmt_count(profile.get('following'))}\n"
    msg += f"  • <b>Total Likes:</b> {_fmt_count(profile.get('likes'))}\n"
    msg += f"  • <b>Videos:</b>    {_fmt_count(profile.get('video_count'))}\n"
    msg += "\n"

    # ── Status Section ───────────────────────────────────────────────────────
    msg += "<b>🛡 STATUS:</b>\n"
    msg += f"  • <b>Verified:</b> {verified_str}\n"
    msg += f"  • <b>Privacy:</b>  {private_str}\n"
    msg += "\n"

    # ── Content Intelligence ─────────────────────────────────────────────────
    activity   = risk.get("activity", "Unknown")
    engagement = risk.get("engagement", "Unknown")
    msg += "<b>📹 CONTENT INTELLIGENCE:</b>\n"
    msg += f"  • <b>Activity Level:</b>  {activity}\n"
    msg += f"  • <b>Engagement Rate:</b> {engagement}\n"
    msg += "\n"

    # ── Risk Analysis ─────────────────────────────────────────────────────────
    imp_str = risk.get("impersonation", "Unknown")
    signals  = risk.get("signals", [])
    msg += "<b>⚠️ RISK ANALYSIS:</b>\n"
    msg += f"  • <b>Risk Score:</b>         {r_em} <code>{score}/100</code>\n"
    msg += f"  • <b>Impersonation Risk:</b> {r_em} {imp_str}\n"
    if signals:
        msg += "  • <b>Signals:</b>\n"
        for sig in signals:
            msg += f"    — <i>{h(sig)}</i>\n"
    msg += "\n"

    if profile.get("is_private"):
        msg += "<i>⚠️ LIMITED DATA AVAILABLE — Account is private.</i>\n"

    msg += f"<code>{sep}</code>"

    if len(msg) > 4000:
        msg = msg[:3997] + "…"
    return msg
