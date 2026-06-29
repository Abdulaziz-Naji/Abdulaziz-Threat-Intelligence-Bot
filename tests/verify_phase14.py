"""
tests/verify_phase14.py — Username OSINT platform list verification.
Verifies the full Lullar-style platform list is present.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from osint_username import PLATFORMS

_PASS = 0
_FAIL = 0

def check(name, condition, extra=''):
    global _PASS, _FAIL
    if condition:
        _PASS += 1
        print(f'  \u2705 PASS  {name}')
    else:
        _FAIL += 1
        print(f'  \u274c FAIL  {name}' + (f'\n       {extra}' if extra else ''))

print('\n\u2550\u2550\u2550 PHASE 14: Username OSINT Platform List \u2550\u2550\u2550\n')

REQUIRED = {
    'Social Media': ['X (Twitter)', 'Instagram', 'Facebook', 'Threads', 'TikTok',
                     'Snapchat', 'Reddit', 'Pinterest', 'Bluesky', 'LinkedIn'],
    'Messaging':    ['Telegram', 'Line', 'Viber', 'Zalo'],
    'Streaming & Gaming': ['Twitch', 'Kick', 'Steam', 'Roblox'],
    'Music & Audio': ['Spotify', 'SoundCloud', 'Bandcamp'],
    'Video': ['Vimeo', 'Rumble', 'Dailymotion'],
    'Writing & Knowledge': ['Medium', 'Substack', 'Quora'],
    'Developer': ['GitHub', 'GitLab', 'Stack Overflow'],
    'Design & Photo': ['Dribbble', 'Behance', 'ArtStation'],
    'Professional': ['Fiverr', 'Upwork', 'Freelancer'],
    'Blogging & Web': ['Linktree', 'WordPress', 'Gravatar'],
    'Commerce': ['Etsy', 'eBay', 'Ko-fi'],
    'Web3 & Crypto': ['Farcaster', 'ENS'],
    'Other': ['Letterboxd', 'Duolingo', 'MyAnimeList'],
}

print('\u2500\u2500 TEST 1: Required platforms present \u2500\u2500')
all_names = list(PLATFORMS.keys())
for category, platforms in REQUIRED.items():
    for platform in platforms:
        check(f'{category}: {platform} present', platform in all_names,
              f'Missing from PLATFORMS list')

print('\n\u2500\u2500 TEST 2: Platform count \u2500\u2500')
check(f'At least 100 platforms defined', len(PLATFORMS) >= 100, f'Got {len(PLATFORMS)}')

print(f"""
\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
  Phase 14 Username OSINT \u2014 {'PASSED' if _FAIL == 0 else 'ISSUES FOUND'}
\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
  Results: {_PASS} passed, {_FAIL} failed
""")
sys.exit(0 if _FAIL == 0 else 1)
