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
    Runs username scans across all platforms using a Semaphore.
    """
    sem = asyncio.Semaphore(15)
    limits = httpx.Limits(max_keepalive_connections=5, max_connections=20)
    
    results = []
    async with httpx.AsyncClient(limits=limits, follow_redirects=True) as client:
        tasks = []
        for name, config in PLATFORMS.items():
            tasks.append(probe_username_platform(client, name, config, username, sem))
        
        completed_count = 0
        total_tasks = len(tasks)
        
        for future in asyncio.as_completed(tasks):
            res = await future
            results.append(res)
            completed_count += 1
            if progress_callback and completed_count % 10 == 0:
                await progress_callback(completed_count, total_tasks)
                
    return results

def compute_confidence_score(results: list) -> int:
    """
    Computes an overall confidence score based on positive findings and their relative strengths.
    """
    positive_results = [r for r in results if r["status"] in ("Found", "Manual Check Required")]
    if not positive_results:
        return 0
    
    total_score = sum(r["confidence"] for r in positive_results)
    return int(total_score / len(positive_results))

def format_report_messages(username: str, results: list) -> list:
    """
    Formats the categorized scanning report into one or more Telegram messages (splitting if needed).
    Only displays Found and Manual Check Required items in the body.
    """
    found_count = len([r for r in results if r["status"] == "Found"])
    manual_count = len([r for r in results if r["status"] == "Manual Check Required"])
    not_found_count = len([
        r for r in results
        if r["status"] == "Not Found" or "Error" in r["status"] or r["status"] == "Timeout"
    ])
    
    confidence = compute_confidence_score(results)
    
    categories = {}
    for r in results:
        cat = r["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(r)
        
    sep = "━━━━━━━━━━━━━━━━━━━━━━"
    
    header = (
        f"🕵️ USERNAME IDENTITY REPORT\n"
        f"{sep}\n\n"
        f"<b>Target</b>          <code>{username}</code>\n\n"
        f"<b>Platforms</b>       {len(results)}\n"
        f"<b>Found</b>           {found_count}\n"
        f"<b>Manual Review</b>   {manual_count}\n"
        f"<b>Not Found</b>       {not_found_count}\n\n"
        f"{sep}\n"
    )
    
    # Pre-defined categories and emojis in order of display
    cat_order = [
        ("Social Media", "🌐 SOCIAL MEDIA"),
        ("Messaging", "💬 MESSAGING"),
        ("Gaming", "🎮 GAMING"),
        ("Streaming", "📺 STREAMING"),
    ]
    
    body_parts = []
    
    for cat_key, cat_title in cat_order:
        items = categories.get(cat_key, [])
        # Only keep Found and Manual Check
        positive_items = [
            i for i in items
            if i["status"] in ("Found", "Manual Check Required")
        ]
        if not positive_items:
            continue
            
        # Sort: Found (🟢) first, then Manual (⚠️)
        positive_items.sort(key=lambda x: 0 if x["status"] == "Found" else 1)
        
        cat_str = f"{cat_title}\n\n"
        for item in positive_items:
            em = "🟢" if item["status"] == "Found" else "⚠️"
            cat_str += f"{em} <a href=\"{item['url']}\">{item['platform']}</a>\n"
            
        body_parts.append(cat_str + "\n" + sep + "\n")
        
    footer = f"<b>Confidence Score: {confidence}%</b>"
    
    messages = []
    current_msg = header
    
    for part in body_parts:
        if len(current_msg) + len(part) + len(footer) > 4000:
            messages.append(current_msg.rstrip())
            current_msg = ""
        current_msg += part
        
    current_msg += footer
    messages.append(current_msg)
    
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
