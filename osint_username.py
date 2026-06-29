"""
osint_username.py - Username & Identity OSINT Discovery Engine.
Generates direct profile links across 140+ platforms (Lullar-style).
No network requests — instant results for manual analyst verification.
"""
import asyncio
import logging

logger = logging.getLogger(__name__)

# ─── Full Lullar-style platform list ──────────────────────────────────────────
PLATFORMS = {

    # ── 👥 SOCIAL MEDIA ───────────────────────────────────────────────────────
    "Spokeo": {
        "url": "https://www.spokeo.com/search?q={u}",
        "category": "Social Media",
    },
    "TikTok": {
        "url": "https://tiktok.com/search?q={u}",
        "category": "Social Media",
    },
    "YouTube": {
        "url": "https://youtube.com/results?search_query={u}",
        "category": "Social Media",
    },
    "Instagram": {
        "url": "https://instagram.com/{u}",
        "category": "Social Media",
    },
    "Facebook": {
        "url": "https://facebook.com/search/top/?q={u}",
        "category": "Social Media",
    },
    "X (Twitter)": {
        "url": "https://x.com/search?q={u}&f=user",
        "category": "Social Media",
    },
    "Bluesky": {
        "url": "https://bsky.app/profile/{u}.bsky.social",
        "category": "Social Media",
    },
    "Threads": {
        "url": "https://threads.com/@{u}",
        "category": "Social Media",
    },
    "Reddit": {
        "url": "https://reddit.com/search/?type=user&q={u}",
        "category": "Social Media",
    },
    "Snapchat": {
        "url": "https://snapchat.com/add/{u}",
        "category": "Social Media",
    },
    "LinkedIn": {
        "url": "https://linkedin.com/search/results/people/?keywords={u}",
        "category": "Social Media",
    },
    "Pinterest": {
        "url": "https://pinterest.com/search/users/?q={u}",
        "category": "Social Media",
    },
    "Mastodon": {
        "url": "https://mastodon.social/@{u}",
        "category": "Social Media",
    },
    "Lemon8": {
        "url": "https://lemon8-app.com/@{u}",
        "category": "Social Media",
    },
    "Spill": {
        "url": "https://spill.com/@{u}",
        "category": "Social Media",
    },
    "Weibo": {
        "url": "https://s.weibo.com/user?q={u}",
        "category": "Social Media",
    },
    "Xiaohongshu": {
        "url": "https://xiaohongshu.com/search_result/?keyword={u}",
        "category": "Social Media",
    },
    "Pikabu": {
        "url": "https://pikabu.ru/@{u}",
        "category": "Social Media",
    },
    "Ekşi Sözlük": {
        "url": "https://eksisozluk.com/biri/{u}",
        "category": "Social Media",
    },
    "Tellonym": {
        "url": "https://tellonym.me/{u}",
        "category": "Social Media",
    },
    "VK": {
        "url": "https://vk.com/search?c%5Bname%5D=1&c%5Bsection%5D=people&c%5Bq%5D={u}",
        "category": "Social Media",
    },
    "ASKfm": {
        "url": "https://ask.fm/{u}",
        "category": "Social Media",
    },
    "Clubhouse": {
        "url": "https://clubhouse.com/@{u}",
        "category": "Social Media",
    },
    "Truth Social": {
        "url": "https://truthsocial.com/@{u}",
        "category": "Social Media",
    },
    "Nextdoor": {
        "url": "https://nextdoor.com/profile/{u}",
        "category": "Social Media",
    },

    # ── 💬 MESSAGING ──────────────────────────────────────────────────────────
    "Telegram": {
        "url": "https://t.me/{u}",
        "category": "Messaging",
    },
    "Line": {
        "url": "https://line.me/R/ti/p/~{u}",
        "category": "Messaging",
    },
    "Viber": {
        "url": "https://chats.viber.com/{u}",
        "category": "Messaging",
    },
    "Zalo": {
        "url": "https://zalo.me/{u}",
        "category": "Messaging",
    },

    # ── 🎮 STREAMING & GAMING ─────────────────────────────────────────────────
    "Twitch": {
        "url": "https://twitch.tv/search?term={u}",
        "category": "Streaming & Gaming",
    },
    "Kick": {
        "url": "https://kick.com/{u}",
        "category": "Streaming & Gaming",
    },
    "Steam": {
        "url": "https://steamcommunity.com/search/users/?text={u}",
        "category": "Streaming & Gaming",
    },
    "Roblox": {
        "url": "https://www.roblox.com/search/users?keyword={u}",
        "category": "Streaming & Gaming",
    },
    "Minecraft": {
        "url": "https://planetminecraft.com/member/{u}",
        "category": "Streaming & Gaming",
    },
    "Crunchyroll": {
        "url": "https://crunchyroll.com/user/{u}",
        "category": "Streaming & Gaming",
    },
    "Chess.com": {
        "url": "https://chess.com/member/{u}",
        "category": "Streaming & Gaming",
    },
    "Lichess": {
        "url": "https://lichess.org/@/{u}",
        "category": "Streaming & Gaming",
    },
    "itch.io": {
        "url": "https://{u}.itch.io",
        "category": "Streaming & Gaming",
    },
    "Scratch": {
        "url": "https://scratch.mit.edu/users/{u}",
        "category": "Streaming & Gaming",
    },
    "osu!": {
        "url": "https://osu.ppy.sh/users/{u}",
        "category": "Streaming & Gaming",
    },
    "Speedrun.com": {
        "url": "https://speedrun.com/users/{u}",
        "category": "Streaming & Gaming",
    },

    # ── 🎵 MUSIC & AUDIO ──────────────────────────────────────────────────────
    "Spotify": {
        "url": "https://open.spotify.com/search/{u}",
        "category": "Music & Audio",
    },
    "SoundCloud": {
        "url": "https://soundcloud.com/{u}",
        "category": "Music & Audio",
    },
    "Bandcamp": {
        "url": "https://{u}.bandcamp.com",
        "category": "Music & Audio",
    },
    "Last.fm": {
        "url": "https://last.fm/search?q={u}",
        "category": "Music & Audio",
    },
    "Smule": {
        "url": "https://smule.com/search?type=user&q={u}",
        "category": "Music & Audio",
    },
    "Freesound": {
        "url": "https://freesound.org/search/?q={u}",
        "category": "Music & Audio",
    },
    "Mixcloud": {
        "url": "https://mixcloud.com/{u}",
        "category": "Music & Audio",
    },
    "Suno": {
        "url": "https://suno.com/@{u}",
        "category": "Music & Audio",
    },
    "Udio": {
        "url": "https://udio.com/creators/{u}",
        "category": "Music & Audio",
    },

    # ── 🎬 VIDEO ──────────────────────────────────────────────────────────────
    "Vimeo": {
        "url": "https://vimeo.com/search/people?q={u}",
        "category": "Video",
    },
    "Rumble": {
        "url": "https://rumble.com/c/{u}",
        "category": "Video",
    },
    "Dailymotion": {
        "url": "https://dailymotion.com/{u}",
        "category": "Video",
    },
    "Bilibili": {
        "url": "https://search.bilibili.com/upuser?keyword={u}",
        "category": "Video",
    },
    "Niconico": {
        "url": "https://nicovideo.jp/search/{u}",
        "category": "Video",
    },
    "9GAG": {
        "url": "https://9gag.com/search?query={u}",
        "category": "Video",
    },

    # ── 📝 WRITING & KNOWLEDGE ────────────────────────────────────────────────
    "Medium": {
        "url": "https://medium.com/@{u}",
        "category": "Writing & Knowledge",
    },
    "Substack": {
        "url": "https://substack.com/@{u}",
        "category": "Writing & Knowledge",
    },
    "Tumblr": {
        "url": "https://{u}.tumblr.com",
        "category": "Writing & Knowledge",
    },
    "Quora": {
        "url": "https://quora.com/search?q={u}",
        "category": "Writing & Knowledge",
    },
    "Zhihu": {
        "url": "https://zhihu.com/search?type=people&q={u}",
        "category": "Writing & Knowledge",
    },
    "Habr": {
        "url": "https://habr.com/users/{u}",
        "category": "Writing & Knowledge",
    },
    "Dzen": {
        "url": "https://dzen.ru/{u}",
        "category": "Writing & Knowledge",
    },
    "Naver Blog": {
        "url": "https://blog.naver.com/{u}",
        "category": "Writing & Knowledge",
    },
    "Tistory": {
        "url": "https://{u}.tistory.com",
        "category": "Writing & Knowledge",
    },
    "Wikipedia": {
        "url": "https://en.wikipedia.org/wiki/User:{u}",
        "category": "Writing & Knowledge",
    },
    "Goodreads": {
        "url": "https://goodreads.com/search?q={u}&search_type=people",
        "category": "Writing & Knowledge",
    },
    "Wattpad": {
        "url": "https://wattpad.com/user/{u}",
        "category": "Writing & Knowledge",
    },
    "DEV Community": {
        "url": "https://dev.to/{u}",
        "category": "Writing & Knowledge",
    },
    "Hashnode": {
        "url": "https://hashnode.com/@{u}",
        "category": "Writing & Knowledge",
    },
    "Hacker News": {
        "url": "https://news.ycombinator.com/user?id={u}",
        "category": "Writing & Knowledge",
    },

    # ── 💻 DEVELOPER ──────────────────────────────────────────────────────────
    "GitHub": {
        "url": "https://github.com/{u}",
        "category": "Developer",
    },
    "GitLab": {
        "url": "https://gitlab.com/search?search={u}",
        "category": "Developer",
    },
    "Codeberg": {
        "url": "https://codeberg.org/{u}",
        "category": "Developer",
    },
    "Stack Overflow": {
        "url": "https://stackoverflow.com/users?tab=Reputation&filter=All&search={u}",
        "category": "Developer",
    },
    "CodePen": {
        "url": "https://codepen.io/{u}",
        "category": "Developer",
    },
    "LeetCode": {
        "url": "https://leetcode.com/u/{u}",
        "category": "Developer",
    },
    "Kaggle": {
        "url": "https://kaggle.com/{u}",
        "category": "Developer",
    },
    "Docker Hub": {
        "url": "https://hub.docker.com/u/{u}",
        "category": "Developer",
    },
    "Replit": {
        "url": "https://replit.com/@{u}",
        "category": "Developer",
    },
    "Product Hunt": {
        "url": "https://producthunt.com/search/users?q={u}",
        "category": "Developer",
    },
    "Bitbucket": {
        "url": "https://bitbucket.org/{u}",
        "category": "Developer",
    },
    "npm": {
        "url": "https://npmjs.com/~{u}",
        "category": "Developer",
    },
    "HackerRank": {
        "url": "https://hackerrank.com/profile/{u}",
        "category": "Developer",
    },
    "Codeforces": {
        "url": "https://codeforces.com/profile/{u}",
        "category": "Developer",
    },
    "Codewars": {
        "url": "https://codewars.com/users/{u}",
        "category": "Developer",
    },
    "Hugging Face": {
        "url": "https://huggingface.co/{u}",
        "category": "Developer",
    },
    "Exercism": {
        "url": "https://exercism.org/profiles/{u}",
        "category": "Developer",
    },

    # ── 🎨 DESIGN & PHOTO ─────────────────────────────────────────────────────
    "Dribbble": {
        "url": "https://dribbble.com/search/users/{u}",
        "category": "Design & Photo",
    },
    "Behance": {
        "url": "https://behance.net/search/users?search={u}",
        "category": "Design & Photo",
    },
    "DeviantArt": {
        "url": "https://deviantart.com/search?q={u}",
        "category": "Design & Photo",
    },
    "Flickr": {
        "url": "https://flickr.com/search/people/?username={u}",
        "category": "Design & Photo",
    },
    "Unsplash": {
        "url": "https://unsplash.com/s/users/{u}",
        "category": "Design & Photo",
    },
    "Pixabay": {
        "url": "https://pixabay.com/users/search/{u}",
        "category": "Design & Photo",
    },
    "VSCO": {
        "url": "https://vsco.co/search/people/{u}",
        "category": "Design & Photo",
    },
    "PicsArt": {
        "url": "https://picsart.com/u/{u}",
        "category": "Design & Photo",
    },
    "Shutterstock": {
        "url": "https://shutterstock.com/g/{u}",
        "category": "Design & Photo",
    },
    "Canva": {
        "url": "https://canva.com/p/{u}",
        "category": "Design & Photo",
    },
    "500px": {
        "url": "https://500px.com/search?q={u}",
        "category": "Design & Photo",
    },
    "Imgur": {
        "url": "https://imgur.com/search?q={u}",
        "category": "Design & Photo",
    },
    "ArtStation": {
        "url": "https://artstation.com/{u}",
        "category": "Design & Photo",
    },
    "Giphy": {
        "url": "https://giphy.com/{u}",
        "category": "Design & Photo",
    },
    "Newgrounds": {
        "url": "https://{u}.newgrounds.com",
        "category": "Design & Photo",
    },
    "Thingiverse": {
        "url": "https://thingiverse.com/{u}",
        "category": "Design & Photo",
    },
    "Pixiv": {
        "url": "https://pixiv.net/en/search_user.php?nick={u}",
        "category": "Design & Photo",
    },
    "Civitai": {
        "url": "https://civitai.com/user/{u}",
        "category": "Design & Photo",
    },
    "Tensor.Art": {
        "url": "https://tensor.art/u/{u}",
        "category": "Design & Photo",
    },
    "Freepik": {
        "url": "https://freepik.com/author/{u}",
        "category": "Design & Photo",
    },

    # ── 💼 PROFESSIONAL ───────────────────────────────────────────────────────
    "Fiverr": {
        "url": "https://fiverr.com/{u}",
        "category": "Professional",
    },
    "ResearchGate": {
        "url": "https://researchgate.net/search/researcher?q={u}",
        "category": "Professional",
    },
    "Wellfound": {
        "url": "https://wellfound.com/u/{u}",
        "category": "Professional",
    },
    "Freelancer": {
        "url": "https://freelancer.com/u/{u}",
        "category": "Professional",
    },
    "Academia": {
        "url": "https://academia.edu/search?utf8=%E2%9C%93&tab=2&q={u}",
        "category": "Professional",
    },
    "Upwork": {
        "url": "https://upwork.com/freelancers/~{u}",
        "category": "Professional",
    },
    "F6S": {
        "url": "https://f6s.com/{u}",
        "category": "Professional",
    },

    # ── 🌐 BLOGGING & WEB ─────────────────────────────────────────────────────
    "Linktree": {
        "url": "https://linktr.ee/{u}",
        "category": "Blogging & Web",
    },
    "Beacons": {
        "url": "https://beacons.ai/{u}",
        "category": "Blogging & Web",
    },
    "Bento": {
        "url": "https://bento.me/{u}",
        "category": "Blogging & Web",
    },
    "WordPress": {
        "url": "https://{u}.wordpress.com",
        "category": "Blogging & Web",
    },
    "Blogspot": {
        "url": "https://{u}.blogspot.com",
        "category": "Blogging & Web",
    },
    "Wix": {
        "url": "https://{u}.wix.com",
        "category": "Blogging & Web",
    },
    "Gravatar": {
        "url": "https://gravatar.com/{u}",
        "category": "Blogging & Web",
    },
    "About.me": {
        "url": "https://about.me/{u}",
        "category": "Blogging & Web",
    },

    # ── 🛒 COMMERCE ───────────────────────────────────────────────────────────
    "Etsy": {
        "url": "https://etsy.com/shop/{u}",
        "category": "Commerce",
    },
    "Depop": {
        "url": "https://depop.com/{u}",
        "category": "Commerce",
    },
    "Poshmark": {
        "url": "https://poshmark.com/closet/{u}",
        "category": "Commerce",
    },
    "eBay": {
        "url": "https://ebay.com/usr/{u}",
        "category": "Commerce",
    },
    "Cash App": {
        "url": "https://cash.app/${u}",
        "category": "Commerce",
    },
    "Buy Me a Coffee": {
        "url": "https://buymeacoffee.com/{u}",
        "category": "Commerce",
    },
    "Ko-fi": {
        "url": "https://ko-fi.com/{u}",
        "category": "Commerce",
    },
    "Gumroad": {
        "url": "https://{u}.gumroad.com",
        "category": "Commerce",
    },
    "OpenSea": {
        "url": "https://opensea.io/{u}",
        "category": "Commerce",
    },
    "Vinted": {
        "url": "https://vinted.com/members/{u}",
        "category": "Commerce",
    },
    "Venmo": {
        "url": "https://venmo.com/u/{u}",
        "category": "Commerce",
    },
    "Patreon": {
        "url": "https://patreon.com/search?q={u}",
        "category": "Commerce",
    },

    # ── ⚡ WEB3 & CRYPTO ──────────────────────────────────────────────────────
    "Farcaster": {
        "url": "https://farcaster.xyz/{u}",
        "category": "Web3 & Crypto",
    },
    "Hey (Lens)": {
        "url": "https://hey.xyz/u/{u}",
        "category": "Web3 & Crypto",
    },
    "ENS": {
        "url": "https://app.ens.domains/{u}.eth",
        "category": "Web3 & Crypto",
    },

    # ── 📌 OTHER ──────────────────────────────────────────────────────────────
    "Letterboxd": {
        "url": "https://letterboxd.com/{u}",
        "category": "Other",
    },
    "Strava": {
        "url": "https://strava.com/athletes/{u}",
        "category": "Other",
    },
    "TradingView": {
        "url": "https://tradingview.com/u/{u}",
        "category": "Other",
    },
    "Trello": {
        "url": "https://trello.com/u/{u}",
        "category": "Other",
    },
    "Disqus": {
        "url": "https://disqus.com/by/{u}",
        "category": "Other",
    },
    "SlideShare": {
        "url": "https://slideshare.net/{u}",
        "category": "Other",
    },
    "Flipboard": {
        "url": "https://flipboard.com/search/{u}",
        "category": "Other",
    },
    "ThemeForest": {
        "url": "https://themeforest.net/user/{u}",
        "category": "Other",
    },
    "OK.ru": {
        "url": "https://ok.ru/search/profiles/{u}",
        "category": "Other",
    },
    "Myspace": {
        "url": "https://myspace.com/{u}",
        "category": "Other",
    },
    "Apple Discussions": {
        "url": "https://discussions.apple.com/profile/{u}",
        "category": "Other",
    },
    "Duolingo": {
        "url": "https://duolingo.com/profile/{u}",
        "category": "Other",
    },
    "MyAnimeList": {
        "url": "https://myanimelist.net/profile/{u}",
        "category": "Other",
    },
    "Anilist": {
        "url": "https://anilist.co/user/{u}",
        "category": "Other",
    },
    "Keybase": {
        "url": "https://keybase.io/{u}",
        "category": "Other",
    },
    "Instructables": {
        "url": "https://instructables.com/member/{u}",
        "category": "Other",
    },
    "Tripadvisor": {
        "url": "https://tripadvisor.com/Profile/{u}",
        "category": "Other",
    },
    "Fandom": {
        "url": "https://community.fandom.com/wiki/User:{u}",
        "category": "Other",
    },
}


async def run_username_scan(username: str, progress_callback=None) -> list:
    """
    Generates profile links instantly without network requests.
    The analyst clicks each link to verify manually.
    """
    results = []
    for name, config in PLATFORMS.items():
        url = config["url"].format(u=username)
        results.append({
            "platform": name,
            "url": url,
            "category": config["category"],
        })
    if progress_callback:
        await progress_callback(len(results), len(results))
    return results


def format_report_messages(username: str, results: list) -> list:
    """
    Formats the OSINT report in Lullar-style: categories with bullet-linked platform names.
    Each link is clickable for manual analyst verification.
    """
    # Group by category
    categories: dict = {}
    for r in results:
        cat = r["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(r)

    sep = "━━━━━━━━━━━━━━━━━━━━━━"

    # Lullar category order with matching emojis
    cat_order = [
        ("Social Media",      "👥 Social Media"),
        ("Messaging",         "💬 Messaging"),
        ("Streaming & Gaming","🎮 Streaming & Gaming"),
        ("Music & Audio",     "🎵 Music & Audio"),
        ("Video",             "🎬 Video"),
        ("Writing & Knowledge","📝 Writing & Knowledge"),
        ("Developer",         "💻 Developer"),
        ("Design & Photo",    "🎨 Design & Photo"),
        ("Professional",      "💼 Professional"),
        ("Blogging & Web",    "🌐 Blogging & Web"),
        ("Commerce",          "🛒 Commerce"),
        ("Web3 & Crypto",     "⚡ Web3 & Crypto"),
        ("Other",             "📌 Other"),
    ]

    header = (
        f"🕵️‍♂️ <b>USERNAME IDENTITY REPORT</b>\n"
        f"<code>{sep}</code>\n\n"
        f"<b>Target</b>          <code>{username}</code>\n"
        f"<b>Platforms</b>       {len(results)}\n\n"
        f"<code>{sep}</code>\n"
    )

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
    """Test helper to run via command line."""
    print(f"Scanning '{username}' across {len(PLATFORMS)} platforms...")

    async def cb(current, total):
        print(f"Progress: {current}/{total}")

    results = await run_username_scan(username, progress_callback=cb)
    msgs = format_report_messages(username, results)
    for idx, msg in enumerate(msgs):
        print(f"--- MESSAGE {idx+1} ---")
        print(msg)
