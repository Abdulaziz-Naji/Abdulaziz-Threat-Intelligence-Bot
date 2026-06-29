"""
osint_instagram.py - Instagram Social Media Intelligence Engine

Strategy (multi-tier fallback):
  Tier 1: i.instagram.com/api/v1/users/web_profile_info/ + x-ig-app-id header
  Tier 2: www.instagram.com/{username}/?__a=1&__d=dis
  Tier 3: HTML scraping of public profile page + embedded JSON extraction
  Tier 4: Degraded metadata from public page title/meta tags

Returns structured InstaProfile with all available public data.
"""
import asyncio
import re
import json
import html as html_lib
import hashlib
from typing import Optional
import httpx


# ─── Browser-realistic headers ────────────────────────────────────────────────

_CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

_BASE_HEADERS = {
    "User-Agent":      _CHROME_UA,
    "Accept":          "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Referer":         "https://www.instagram.com/",
    "Origin":          "https://www.instagram.com",
    "Sec-Fetch-Dest":  "empty",
    "Sec-Fetch-Mode":  "cors",
    "Sec-Fetch-Site":  "same-origin",
}

_IG_APP_ID = "936619743392459"  # Instagram Web App ID (public constant)


# ─── Result data class (dict-based for simplicity) ────────────────────────────

def _empty_profile(username: str) -> dict:
    return {
        "username":          username,
        "full_name":         "",
        "bio":               "",
        "profile_pic_url":   "",
        "external_url":      "",
        "followers":         None,
        "following":         None,
        "posts":             None,
        "highlights":        None,
        "is_verified":       False,
        "is_private":        False,
        "is_business":       False,
        "business_category": "",
        "account_type":      "",
        "is_professional":   False,
        "found":             False,
        "data_tier":         "",   # which strategy succeeded
        "error":             "",
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  Tier 1 — i.instagram.com REST endpoint
# ═══════════════════════════════════════════════════════════════════════════════

async def _try_insta_api(username: str, client: httpx.AsyncClient) -> Optional[dict]:
    """Try the internal Instagram REST API endpoint."""
    url = f"https://i.instagram.com/api/v1/users/web_profile_info/?username={username}"
    headers = {**_BASE_HEADERS, "x-ig-app-id": _IG_APP_ID}
    try:
        r = await client.get(url, headers=headers, timeout=15)
        if r.status_code != 200:
            return None
        data = r.json()
        user = data.get("data", {}).get("user")
        if not user:
            return None
        return _parse_api_user(user)
    except Exception:
        return None


def _parse_api_user(user: dict) -> dict:
    """Parse the user dict from the Instagram API response."""
    p = _empty_profile(user.get("username", ""))
    p["username"]          = user.get("username", "")
    p["full_name"]         = user.get("full_name", "") or ""
    p["bio"]               = user.get("biography", "") or ""
    p["profile_pic_url"]   = user.get("profile_pic_url_hd") or user.get("profile_pic_url", "") or ""
    p["external_url"]      = user.get("external_url", "") or ""
    p["followers"]         = _get_count(user, "edge_followed_by")
    p["following"]         = _get_count(user, "edge_follow")
    p["posts"]             = _get_count(user, "edge_owner_to_timeline_media")
    p["is_verified"]       = bool(user.get("is_verified", False))
    p["is_private"]        = bool(user.get("is_private", False))
    p["is_business"]       = bool(user.get("is_business_account", False))
    p["business_category"] = user.get("business_category_name", "") or ""
    p["is_professional"]   = bool(user.get("is_professional_account", False))
    p["found"]             = True
    p["data_tier"]         = "API (Tier 1)"
    return p


def _get_count(user: dict, key: str) -> Optional[int]:
    """Extract count from edge dict."""
    val = user.get(key, {})
    if isinstance(val, dict):
        return val.get("count")
    return None


# ═══════════════════════════════════════════════════════════════════════════════
#  Tier 2 — ?__a=1 JSON endpoint
# ═══════════════════════════════════════════════════════════════════════════════

async def _try_insta_a1(username: str, client: httpx.AsyncClient) -> Optional[dict]:
    """Try the legacy /?__a=1 JSON endpoint."""
    url = f"https://www.instagram.com/{username}/?__a=1&__d=dis"
    headers = {**_BASE_HEADERS, "x-ig-app-id": _IG_APP_ID}
    try:
        r = await client.get(url, headers=headers, timeout=15)
        if r.status_code != 200:
            return None
        data = r.json()
        user = data.get("graphql", {}).get("user") or data.get("data", {}).get("user")
        if not user:
            return None
        return _parse_graphql_user(user)
    except Exception:
        return None


def _parse_graphql_user(user: dict) -> dict:
    """Parse a GraphQL-style user object."""
    p = _empty_profile(user.get("username", ""))
    p["username"]        = user.get("username", "")
    p["full_name"]       = user.get("full_name", "") or ""
    p["bio"]             = user.get("biography", "") or ""
    p["profile_pic_url"] = user.get("profile_pic_url_hd") or user.get("profile_pic_url", "") or ""
    p["external_url"]    = user.get("external_url", "") or ""
    p["followers"]       = _get_count(user, "edge_followed_by")
    p["following"]       = _get_count(user, "edge_follow")
    p["posts"]           = _get_count(user, "edge_owner_to_timeline_media")
    p["is_verified"]     = bool(user.get("is_verified", False))
    p["is_private"]      = bool(user.get("is_private", False))
    p["is_business"]     = bool(user.get("is_business_account", False))
    p["found"]           = True
    p["data_tier"]       = "GraphQL (Tier 2)"
    return p


# ═══════════════════════════════════════════════════════════════════════════════
#  Tier 3 — HTML scraping + embedded JSON extraction
# ═══════════════════════════════════════════════════════════════════════════════

async def _try_html_scrape(username: str, client: httpx.AsyncClient) -> Optional[dict]:
    """Scrape the public Instagram profile HTML page."""
    url = f"https://www.instagram.com/{username}/"
    headers = {**_BASE_HEADERS, "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate"}
    try:
        r = await client.get(url, headers=headers, timeout=20)
        if r.status_code == 404:
            p = _empty_profile(username)
            p["error"]    = "Profile not found (404)"
            p["found"]    = False
            p["data_tier"] = "HTML (Tier 3 - 404)"
            return p
        if r.status_code != 200:
            return None
        return _parse_html(username, r.text)
    except Exception:
        return None


def _parse_html(username: str, html: str) -> Optional[dict]:
    """Extract profile data from Instagram's HTML page."""
    p = _empty_profile(username)
    p["data_tier"] = "HTML (Tier 3)"

    # ── Try embedded __additionalDataLoaded / window._sharedData ─────────────
    shared_match = re.search(r'window\._sharedData\s*=\s*(\{.+?\});</script>', html, re.DOTALL)
    if shared_match:
        try:
            data    = json.loads(shared_match.group(1))
            entries = data.get("entry_data", {}).get("ProfilePage", [{}])
            user    = entries[0].get("graphql", {}).get("user", {}) if entries else {}
            if user:
                parsed = _parse_graphql_user(user)
                parsed["data_tier"] = "HTML SharedData (Tier 3)"
                return parsed
        except Exception:
            pass

    # ── Try script tags with profile data ────────────────────────────────────
    script_matches = re.findall(r'<script type="application/ld\+json">(.*?)</script>', html, re.DOTALL)
    for script in script_matches:
        try:
            ld = json.loads(script)
            if ld.get("@type") == "ProfilePage" or "Person" in str(ld.get("@type", "")):
                name = ld.get("name", "") or ld.get("alternateName", "")
                desc = ld.get("description", "")
                img  = ld.get("image", "")
                if isinstance(img, dict):
                    img = img.get("url", "")
                p["full_name"]       = name
                p["bio"]             = desc
                p["profile_pic_url"] = img
                p["found"]           = True
        except Exception:
            pass

    # ── Extract from meta tags ────────────────────────────────────────────────
    og_title = re.search(r'<meta property="og:title" content="([^"]*)"', html)
    og_desc  = re.search(r'<meta property="og:description" content="([^"]*)"', html)
    og_image = re.search(r'<meta property="og:image" content="([^"]*)"', html)

    if og_title:
        raw_title = html_lib.unescape(og_title.group(1))
        # Format: "Full Name (@username) • Instagram..."
        name_match = re.match(r'^(.+?)\s*[\(\@]', raw_title)
        if name_match:
            p["full_name"] = name_match.group(1).strip()
    if og_desc:
        raw_desc = html_lib.unescape(og_desc.group(1))
        # Format: "X Followers, Y Following, Z Posts - See Instagram photos..."
        follower_m  = re.search(r'([\d,\.]+[KMB]?)\s+Followers', raw_desc)
        following_m = re.search(r'([\d,\.]+[KMB]?)\s+Following', raw_desc)
        posts_m     = re.search(r'([\d,\.]+[KMB]?)\s+Posts', raw_desc)
        if follower_m:
            p["followers"] = _parse_count_str(follower_m.group(1))
        if following_m:
            p["following"] = _parse_count_str(following_m.group(1))
        if posts_m:
            p["posts"] = _parse_count_str(posts_m.group(1))
    if og_image:
        p["profile_pic_url"] = og_image.group(1)

    # ── Check for private indicator in page ───────────────────────────────────
    if '"is_private":true' in html or 'This Account is Private' in html:
        p["is_private"] = True
    if '"is_verified":true' in html:
        p["is_verified"] = True
    if '"is_business_account":true' in html:
        p["is_business"] = True

    # ── Check if profile exists at all ────────────────────────────────────────
    if 'Sorry, this page' in html or 'Page Not Found' in html:
        p["found"]  = False
        p["error"]  = "Profile not found"
        return p

    # If we got a username from the URL we can confirm it exists
    if f'@{username}' in html or f'"username":"{username}"' in html.lower():
        p["found"] = True

    return p


def _parse_count_str(s: str) -> Optional[int]:
    """Convert '1.5M', '234K', '12,345' to int."""
    s = s.strip().replace(",", "")
    try:
        if s.endswith("K"):
            return int(float(s[:-1]) * 1_000)
        if s.endswith("M"):
            return int(float(s[:-1]) * 1_000_000)
        if s.endswith("B"):
            return int(float(s[:-1]) * 1_000_000_000)
        return int(float(s))
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
#  Risk Analysis
# ═══════════════════════════════════════════════════════════════════════════════

_BRAND_KEYWORDS = [
    "official", "real", "original", "verified", "actual", "authentic",
    "support", "help", "customer", "service", "team", "global", "admin",
    "security", "trust", "safe", "paypal", "microsoft", "apple", "google",
    "amazon", "meta", "instagram", "tiktok", "facebook", "twitter", "telegram",
    "crypto", "bitcoin", "nft", "investment", "bank", "trading",
]

def _analyze_risk(profile: dict) -> dict:
    """
    Compute impersonation risk and account suspicion signals.
    Returns a risk dict.
    """
    username = profile.get("username", "").lower()
    full_name = profile.get("full_name", "").lower()
    bio = profile.get("bio", "").lower()
    followers = profile.get("followers") or 0
    following = profile.get("following") or 0
    posts = profile.get("posts") or 0
    is_verified = profile.get("is_verified", False)
    is_private = profile.get("is_private", False)

    signals = []
    risk_score = 0

    # ── Username pattern signals ──────────────────────────────────────────────
    # Trailing digits (impersonation pattern)
    if re.search(r'\d{2,}$', username):
        signals.append("Username ends with digits (common impersonation pattern)")
        risk_score += 15

    # Very long username
    if len(username) > 25:
        signals.append("Unusually long username")
        risk_score += 8

    # Lots of dots/underscores
    if username.count("_") + username.count(".") >= 3:
        signals.append("Multiple separators in username")
        risk_score += 10

    # Brand keyword in username
    for kw in _BRAND_KEYWORDS:
        if kw in username:
            signals.append(f"Brand/trust keyword in username: '{kw}'")
            risk_score += 20
            break

    # Brand keyword in bio
    for kw in ["giveaway", "free", "win", "prize", "dm for", "send crypto", "investment"]:
        if kw in bio:
            signals.append(f"Suspicious bio keyword: '{kw}'")
            risk_score += 15
            break

    # ── Follower ratio signals ────────────────────────────────────────────────
    if followers > 0 and following > 0:
        ratio = following / followers
        if ratio > 10 and followers < 500:
            signals.append("High following-to-follower ratio (potential bot/follow-farm)")
            risk_score += 20
        if followers > 10_000 and posts < 5:
            signals.append("High followers with very few posts (bought followers suspected)")
            risk_score += 25
        if followers > 50_000 and not is_verified:
            signals.append("Large unverified account (elevated impersonation risk)")
            risk_score += 10

    # ── Account characteristics ───────────────────────────────────────────────
    if is_private and followers == 0:
        signals.append("Private account with no visible followers")
        risk_score += 5

    if posts == 0 and not is_private:
        signals.append("Public account with zero posts")
        risk_score += 10

    # Cap
    risk_score = min(risk_score, 100)

    # ── Activity estimation ───────────────────────────────────────────────────
    if posts is not None and posts > 100 and followers is not None and followers > 1000:
        activity = "High"
    elif posts is not None and posts > 20:
        activity = "Medium"
    elif posts is not None and posts > 0:
        activity = "Low"
    else:
        activity = "Unknown"

    # ── Impersonation likelihood ──────────────────────────────────────────────
    if risk_score >= 60:
        impersonation = "High"
        imp_em = "🔴"
    elif risk_score >= 35:
        impersonation = "Medium"
        imp_em = "🟠"
    elif risk_score >= 15:
        impersonation = "Low"
        imp_em = "🟡"
    else:
        impersonation = "Minimal"
        imp_em = "🟢"

    return {
        "risk_score":          risk_score,
        "impersonation":       impersonation,
        "impersonation_em":    imp_em,
        "activity":            activity,
        "signals":             signals[:5],
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  Main Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

async def investigate_instagram(username: str) -> dict:
    """
    Full Instagram intelligence investigation for a username.
    Tries all tiers in order. Returns profile + risk analysis.
    """
    username = username.lstrip("@").strip()

    async with httpx.AsyncClient(
        timeout=20,
        follow_redirects=True,
        headers={"User-Agent": _CHROME_UA},
    ) as client:
        profile = None

        # Tier 1: Internal REST API
        profile = await _try_insta_api(username, client)

        # Tier 2: ?__a=1 legacy endpoint
        if not profile or not profile.get("found"):
            await asyncio.sleep(0.5)
            t2 = await _try_insta_a1(username, client)
            if t2 and t2.get("found"):
                profile = t2

        # Tier 3: HTML scraping
        if not profile or not profile.get("found"):
            await asyncio.sleep(0.5)
            t3 = await _try_html_scrape(username, client)
            if t3:
                if profile and not profile.get("found"):
                    # Merge HTML data into existing
                    for k in ("full_name", "bio", "profile_pic_url", "followers",
                               "following", "posts", "is_private", "is_verified", "is_business"):
                        if not profile.get(k) and t3.get(k):
                            profile[k] = t3[k]
                    if t3.get("found"):
                        profile["found"] = True
                    profile["data_tier"] = t3.get("data_tier", "HTML (Tier 3)")
                else:
                    profile = t3

    if not profile:
        profile = _empty_profile(username)
        profile["error"] = "All extraction strategies failed"

    # Attach risk analysis
    profile["risk"] = _analyze_risk(profile)
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


def format_instagram_report(profile: dict) -> str:
    sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
    h   = html_lib.escape
    username = profile.get("username", "unknown")

    if not profile.get("found"):
        err = profile.get("error", "Unknown error")
        return (
            f"📱 <b>Social Media Intelligence</b>\n"
            f"<code>{sep}</code>\n\n"
            f"🔹 <b>Platform:</b> Instagram\n"
            f"🔹 <b>Target:</b> <code>@{h(username)}</code>\n\n"
            f"❌ <b>Profile not found or data unavailable.</b>\n"
            f"<i>{h(err)}</i>\n\n"
            f"<i>Account may be private, deleted, or blocked from automated queries.</i>\n"
            f"<code>{sep}</code>"
        )

    risk  = profile.get("risk", {})
    r_em  = risk.get("impersonation_em", "⚪")
    score = risk.get("risk_score", 0)

    # Status icons
    verified_str  = "✅ Yes" if profile.get("is_verified")   else "❌ No"
    private_str   = "🔒 Private" if profile.get("is_private") else "🌐 Public"
    business_str  = profile.get("business_category") or ("Business/Creator" if profile.get("is_business") else "Personal")

    # Profile pic link
    pic_url = profile.get("profile_pic_url", "")
    ext_url = profile.get("external_url", "")

    msg = (
        f"📱 <b>Social Media Intelligence Report</b>\n"
        f"<code>{sep}</code>\n\n"
        f"🔹 <b>Platform:</b> Instagram\n"
        f"🔹 <b>Target:</b> <a href=\"https://instagram.com/{h(username)}\">@{h(username)}</a>\n"
        f"🔹 <b>Data Source:</b> <i>{profile.get('data_tier', 'Unknown')}</i>\n\n"
    )

    # ── Profile Section ──────────────────────────────────────────────────────
    msg += f"<b>👤 PROFILE:</b>\n"
    if profile.get("full_name"):
        msg += f"  • <b>Name:</b> {h(profile['full_name'])}\n"
    if profile.get("bio"):
        bio_preview = h(profile["bio"][:180])
        msg += f"  • <b>Bio:</b> <i>{bio_preview}</i>\n"
    if ext_url:
        msg += f"  • <b>Link:</b> <a href=\"{h(ext_url)}\">{h(ext_url[:50])}</a>\n"
    if pic_url:
        msg += f"  • <b>Photo:</b> <a href=\"{h(pic_url)}\">View Profile Picture</a>\n"
    msg += "\n"

    # ── Metrics Section ──────────────────────────────────────────────────────
    msg += f"<b>📊 METRICS:</b>\n"
    msg += f"  • <b>Followers:</b> {_fmt_count(profile.get('followers'))}\n"
    msg += f"  • <b>Following:</b> {_fmt_count(profile.get('following'))}\n"
    msg += f"  • <b>Posts:</b>     {_fmt_count(profile.get('posts'))}\n"
    msg += "\n"

    # ── Status Section ───────────────────────────────────────────────────────
    msg += f"<b>🛡 STATUS:</b>\n"
    msg += f"  • <b>Verified:</b>  {verified_str}\n"
    msg += f"  • <b>Privacy:</b>   {private_str}\n"
    msg += f"  • <b>Type:</b>      {h(business_str)}\n"
    msg += "\n"

    # ── Risk Analysis ─────────────────────────────────────────────────────────
    activity = risk.get("activity", "Unknown")
    imp_str  = risk.get("impersonation", "Unknown")
    signals  = risk.get("signals", [])

    msg += f"<b>⚠️ RISK ANALYSIS:</b>\n"
    msg += f"  • <b>Risk Score:</b> {r_em} <code>{score}/100</code>\n"
    msg += f"  • <b>Impersonation Risk:</b> {r_em} {imp_str}\n"
    msg += f"  • <b>Account Activity:</b> {activity}\n"

    if signals:
        msg += f"  • <b>Signals:</b>\n"
        for sig in signals:
            msg += f"    — <i>{h(sig)}</i>\n"
    msg += "\n"

    if profile.get("is_private"):
        msg += "<i>⚠️ LIMITED DATA AVAILABLE — Account is private.</i>\n"

    msg += f"<code>{sep}</code>"

    # Enforce Telegram limit
    if len(msg) > 4000:
        msg = msg[:3997] + "…"
    return msg
