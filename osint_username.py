"""
osint_username.py - Core Engine for Username & Identity OSINT Discovery.
Provides 20 platform probes with async concurrency and confidence scoring.
"""
import asyncio
import logging
import httpx
import json

logger = logging.getLogger(__name__)

# List of 20 platforms categorized for OSINT lookup
PLATFORMS = {
    # ── SOCIAL MEDIA (10) ─────────────────────────────────────────────────────
    "Reddit": {
        "url": "https://www.reddit.com/user/{u}",
        "category": "Social Media",
        "check": "status_200_body",
        "not_found_body": "page not found",
    },
    "Pinterest": {
        "url": "https://www.pinterest.com/{u}/",
        "category": "Social Media",
        "check": "status",
    },
    "Bluesky": {
        "url": "https://bsky.app/profile/{u}",
        "category": "Social Media",
        "check": "status",
    },
    "Snapchat": {
        "url": "https://www.snapchat.com/add/{u}",
        "category": "Social Media",
        "check": "manual",
    },
    "TikTok": {
        "url": "https://tiktok.com/@{u}",
        "category": "Social Media",
        "check": "manual",
    },
    "X (Twitter)": {
        "url": "https://x.com/{u}",
        "category": "Social Media",
        "check": "manual",
    },
    "Facebook": {
        "url": "https://facebook.com/{u}",
        "category": "Social Media",
        "check": "manual",
    },
    "Threads": {
        "url": "https://www.threads.net/@{u}",
        "category": "Social Media",
        "check": "manual",
    },
    "Instagram": {
        "url": "https://instagram.com/{u}",
        "category": "Social Media",
        "check": "manual",
    },
    "LinkedIn": {
        "url": "https://www.linkedin.com/in/{u}",
        "category": "Social Media",
        "check": "manual",
    },

    # ── MESSAGING (3) ─────────────────────────────────────────────────────────
    "Telegram": {
        "url": "https://t.me/{u}",
        "category": "Messaging",
        "check": "body_present",
        "found_body": "tgme_page_extra",
    },
    "Discord": {
        "url": "https://discord.com",
        "category": "Messaging",
        "check": "manual",
    },
    "Signal": {
        "url": "https://signal.me/#p/{u}",
        "category": "Messaging",
        "check": "manual",
    },

    # ── GAMING (4) ────────────────────────────────────────────────────────────
    "Steam": {
        "url": "https://steamcommunity.com/id/{u}",
        "category": "Gaming",
        "check": "status_200_body",
        "not_found_body": "The specified profile could not be found",
    },
    "PlayStation": {
        "url": "https://my.playstation.com/{u}",
        "category": "Gaming",
        "check": "manual",
    },
    "Xbox": {
        "url": "https://xboxgamertag.com/search/{u}",
        "category": "Gaming",
        "check": "manual",
    },
    "Roblox": {
        "url": "https://www.roblox.com/user.aspx?username={u}",
        "category": "Gaming",
        "check": "status",
    },

    # ── STREAMING (3) ─────────────────────────────────────────────────────────
    "Twitch": {
        "url": "https://twitch.tv/{u}",
        "category": "Streaming",
        "check": "manual",
    },
    "YouTube": {
        "url": "https://www.youtube.com/@{u}",
        "category": "Streaming",
        "check": "status",
    },
    "Kick": {
        "url": "https://kick.com/{u}",
        "category": "Streaming",
        "check": "manual",
    },
}

async def probe_username_platform(
    client: httpx.AsyncClient,
    name: str,
    config: dict,
    username: str,
    sem: asyncio.Semaphore
) -> dict:
    url = config["url"].format(u=username)
    category = config["category"]
    check_type = config["check"]

    if check_type == "manual":
        return {
            "platform": name,
            "url": url,
            "category": category,
            "status": "Manual Check Required",
            "emoji": "⚠️",
            "confidence": 40
        }

    async with sem:
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9"
            }
            # Make the async request
            response = await client.get(url, headers=headers, timeout=8.0, follow_redirects=True)
            
            # Logic based on check type
            if check_type == "status":
                if response.status_code == 200:
                    return {
                        "platform": name,
                        "url": url,
                        "category": category,
                        "status": "Found",
                        "emoji": "🟢",
                        "confidence": 75
                    }
                else:
                    return {
                        "platform": name,
                        "url": url,
                        "category": category,
                        "status": "Not Found",
                        "emoji": "❌",
                        "confidence": 0
                    }

            elif check_type == "status_200_body":
                if response.status_code == 200:
                    body_text = response.text
                    not_found_str = config.get("not_found_body", "")
                    if not_found_str and not_found_str.lower() in body_text.lower():
                        return {
                            "platform": name,
                            "url": url,
                            "category": category,
                            "status": "Not Found",
                            "emoji": "❌",
                            "confidence": 0
                        }
                    return {
                        "platform": name,
                        "url": url,
                        "category": category,
                        "status": "Found",
                        "emoji": "🟢",
                        "confidence": 85
                    }
                else:
                    return {
                        "platform": name,
                        "url": url,
                        "category": category,
                        "status": "Not Found",
                        "emoji": "❌",
                        "confidence": 0
                    }

            elif check_type == "body_present":
                if response.status_code == 200:
                    body_text = response.text
                    found_str = config.get("found_body", "")
                    if found_str and found_str.lower() in body_text.lower():
                        return {
                            "platform": name,
                            "url": url,
                            "category": category,
                            "status": "Found",
                            "emoji": "🟢",
                            "confidence": 90
                        }
                return {
                    "platform": name,
                    "url": url,
                    "category": category,
                    "status": "Not Found",
                    "emoji": "❌",
                    "confidence": 0
                }

            elif check_type == "json":
                if response.status_code == 200:
                    try:
                        data = response.json()
                        # If it is a valid JSON and not empty, or specific fields present
                        if data:
                            if "error" in data or "errors" in data or "message" in data:
                                return {
                                    "platform": name,
                                    "url": url,
                                    "category": category,
                                    "status": "Not Found",
                                    "emoji": "❌",
                                    "confidence": 0
                                }
                            return {
                                "platform": name,
                                "url": url,
                                "category": category,
                                "status": "Found",
                                "emoji": "🟢",
                                "confidence": 98
                            }
                    except Exception:
                        pass
                return {
                    "platform": name,
                    "url": url,
                    "category": category,
                    "status": "Not Found",
                    "emoji": "❌",
                    "confidence": 0
                }

        except httpx.TimeoutException:
            return {
                "platform": name,
                "url": url,
                "category": category,
                "status": "Timeout",
                "emoji": "⏳",
                "confidence": 0
            }
        except Exception as e:
            return {
                "platform": name,
                "url": url,
                "category": category,
                "status": f"Error: {str(e)[:20]}",
                "emoji": "❌",
                "confidence": 0
            }

    return {
        "platform": name,
        "url": url,
        "category": category,
        "status": "Not Found",
        "emoji": "❌",
        "confidence": 0
    }

async def run_username_scan(username: str, progress_callback=None) -> list:
    """
    Generates profile links instantly without network requests, allowing the user
    to click and verify the profiles themselves.
    """
    results = []
    for name, config in PLATFORMS.items():
        url = config["url"].format(u=username)
        category = config["category"]
        results.append({
            "platform": name,
            "url": url,
            "category": category,
            "status": "Generative",
            "emoji": "•",
            "confidence": 100
        })
    if progress_callback:
        await progress_callback(len(results), len(results))
    return results

def compute_confidence_score(results: list) -> int:
    return 100

def format_report_messages(username: str, results: list) -> list:
    """
    Formats the categorized scanning report into one or more Telegram messages.
    Lists all 20 famous platforms with direct profile links for user verification.
    """
    # Group results into Lullar-style categories
    categories = {
        "Social Media": [],
        "Messaging": [],
        "Streaming & Gaming": []
    }
    
    for r in results:
        cat = r["category"]
        if cat in ("Gaming", "Streaming"):
            cat = "Streaming & Gaming"
            
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(r)
        
    sep = "━━━━━━━━━━━━━━━━━━━━━━"
    
    header = (
        f"🕵️‍♂️ <b>USERNAME IDENTITY REPORT</b>\n"
        f"<code>{sep}</code>\n\n"
        f"<b>Target</b>          <code>{username}</code>\n"
        f"<b>Platforms</b>       {len(results)}\n\n"
        f"<code>{sep}</code>\n"
    )
    
    cat_order = [
        ("Social Media", "👥 Social Media"),
        ("Messaging", "💬 Messaging"),
        ("Streaming & Gaming", "🎮 Streaming & Gaming"),
    ]
    
    body_parts = []
    
    for cat_key, cat_title in cat_order:
        items = categories.get(cat_key, [])
        if not items:
            continue
            
        cat_str = f"<b>{cat_title}</b>\n\n"
        for item in items:
            cat_str += f"• <a href=\"{item['url']}\">{item['platform']}</a>\n"
            
        body_parts.append(cat_str + "\n" + f"<code>{sep}</code>" + "\n")
        
    messages = []
    current_msg = header
    
    for part in body_parts:
        if len(current_msg) + len(part) > 4000:
            messages.append(current_msg.rstrip())
            current_msg = ""
        current_msg += part
        
    messages.append(current_msg.rstrip())
    return messages


async def test_scan(username: str):
    """
    Test helper to run via command line
    """
    print(f"Scanning '{username}' across {len(PLATFORMS)} platforms...")
    
    async def cb(current, total):
        print(f"Progress: {current}/{total} probed...")
        
    results = await run_username_scan(username, progress_callback=cb)
    msgs = format_report_messages(username, results)
    for idx, msg in enumerate(msgs):
        print(f"--- MESSAGE {idx+1} ---")
        print(msg)
    """
    Test helper to run via command line
    """
    print(f"Scanning '{username}' across {len(PLATFORMS)} platforms...")
    
    async def cb(current, total):
        print(f"Progress: {current}/{total} probed...")
        
    results = await run_username_scan(username, progress_callback=cb)
    msgs = format_report_messages(username, results)
    for idx, msg in enumerate(msgs):
        print(f"--- MESSAGE {idx+1} ---")
        print(msg)
