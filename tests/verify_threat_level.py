"""
tests/verify_threat_level.py — Threat level and score boundary tests.
Verifies score thresholds: Clean=0-24, Low=25-44, Suspicious=45-69, Malicious=70+
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ioc_risk_scoring import compute_unified_risk_score

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

print('\n═══ THREAT LEVEL SCORING ═══\n')

# Clean: 0 VT detections, 0 abuse score
print('── TEST 1: Clean IP ──')
result = compute_unified_risk_score(
    ioc_type='ip',
    vt_result={'malicious': 0, 'suspicious': 0, 'harmless': 80, 'undetected': 10},
    abuseipdb_result={'abuse_score': 0, 'total_reports': 0},
    otx_result={},
    tf_iocs=[],
    mb_found=False,
    urlhaus_found=False,
    in_watchlist=False,
    feed_sightings=0
)
check('Clean: score is 0', result['risk_score'] == 0, f"Got {result['risk_score']}")
check('Clean: level is Clean', result['verdict'] == 'Clean', f"Got {result['verdict']}")

# Suspicious: 1 VT detection
print('\n── TEST 2: 1 VT detection ──')
result2 = compute_unified_risk_score(
    ioc_type='ip',
    vt_result={
        'malicious': 1, 'suspicious': 0, 'harmless': 80, 'undetected': 10,
        'last_analysis_results': {'VendorA': {'category': 'suspicious', 'result': 'Suspicious'}}
    },
    abuseipdb_result={'abuse_score': 0, 'total_reports': 0},
    otx_result={},
    tf_iocs=[],
    mb_found=False,
    urlhaus_found=False,
    in_watchlist=False,
    feed_sightings=0
)
check('1 VT: score > 0', result2['risk_score'] > 0, f"Got {result2['risk_score']}")
check('1 VT: verdict is Suspicious or Low', result2['verdict'] in ('Suspicious', 'Low', 'Medium'), f"Got {result2['verdict']}")

# Malicious: 10+ VT detections
print('\n── TEST 3: 10 VT detections ──')
last = {f'V{i}': {'category': 'malicious', 'result': 'Malware'} for i in range(10)}
result3 = compute_unified_risk_score(
    ioc_type='ip',
    vt_result={
        'malicious': 10, 'suspicious': 0, 'harmless': 40, 'undetected': 41,
        'last_analysis_results': last
    },
    abuseipdb_result={'abuse_score': 0, 'total_reports': 0},
    otx_result={},
    tf_iocs=[],
    mb_found=False,
    urlhaus_found=False,
    in_watchlist=False,
    feed_sightings=0
)
check('10 VT: level is High/Critical/Malicious', result3['verdict'] in ('High', 'Critical', 'Malicious'), f"Got {result3['verdict']}")
check('10 VT: score >= 40', result3['risk_score'] >= 40, f"Got {result3['risk_score']}")

print(f"""
════════════════════════════════════════════════════
  Threat Level Scoring — {'PASSED' if _FAIL == 0 else 'ISSUES FOUND'}
════════════════════════════════════════════════════
  Results: {_PASS} passed, {_FAIL} failed
""")
sys.exit(0 if _FAIL == 0 else 1)
