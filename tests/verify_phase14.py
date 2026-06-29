"""
tests/verify_phase14.py — Username OSINT platform list verification.
Verifies the 20 curated platforms are present and categories are correct.
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

print('\n═══ PHASE 14: Username OSINT Platform List ═══\n')

REQUIRED = {
    'Social Media': ['X (Twitter)', 'Instagram', 'Facebook', 'Threads', 'TikTok', 'Snapchat', 'Reddit', 'Pinterest', 'Bluesky', 'LinkedIn'],
    'Messaging':    ['Telegram', 'Discord', 'Signal'],
    'Gaming':       ['Steam', 'PlayStation', 'Xbox', 'Roblox'],
    'Streaming':    ['Twitch', 'YouTube', 'Kick'],
}

REMOVED_CATEGORIES = ['Developer', 'Design', 'Writing', 'Academic', 'Lifestyle', 'Music', 'Link-in-Bio']

print('── TEST 1: Required platforms present ──')
all_names = list(PLATFORMS.keys())
for category, platforms in REQUIRED.items():
    for platform in platforms:
        check(f'{category}: {platform} present', platform in all_names, f'Missing from PLATFORMS list')

print('\n── TEST 2: Removed categories gone ──')
all_cats = [info.get('category', '') for info in PLATFORMS.values()]
for removed in REMOVED_CATEGORIES:
    found = any(removed.lower() in c.lower() for c in all_cats)
    check(f'Category "{removed}" removed', not found, f'Still found in PLATFORMS')

print('\n── TEST 3: Platform count ──')
check(f'At least 20 platforms defined', len(PLATFORMS) >= 20, f'Got {len(PLATFORMS)}')

print(f"""
════════════════════════════════════════════════════
  Phase 14 Username OSINT — {'PASSED' if _FAIL == 0 else 'ISSUES FOUND'}
════════════════════════════════════════════════════
  Results: {_PASS} passed, {_FAIL} failed
""")
sys.exit(0 if _FAIL == 0 else 1)
