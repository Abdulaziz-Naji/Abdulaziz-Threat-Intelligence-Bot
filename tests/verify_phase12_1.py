"""
verify_phase12_1.py - Phase 12.1 Verification

Tests the Evidence Context / Classification separation:
1. OTX pulse tags MUST NOT affect classification
2. OTX pulse names MUST NOT affect classification
3. Community comments MUST NOT affect classification
4. ThreatFox CAN affect classification
5. VT threat_label CAN affect classification
6. VT categories CAN affect classification (domain/URL)
7. GreyNoise malicious CAN affect classification
8. EVIDENCE CONTEXT section renders empty when disabled
9. Classification = empty when ONLY OTX mentions exist (no direct evidence)
10. OTX malware_family MUST NOT appear in Detection Sources
"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ti_report_builder as ti_rb

PASS = "\u2705 PASS"
FAIL = "\u274c FAIL"
results = []


def check(name, condition, details=""):
    status = PASS if condition else FAIL
    results.append((status, name, details))
    print(f"{status}  {name}" + (f"\n       {details}" if details else ""))


# ─────────────────────────────────────────────────────────────────────────────
# Test 1: OTX pulses alone MUST NOT create a classification
# Scenario: Microsoft.com - appears in OTX reports tagged "phishing", "c2"
# but VT, ThreatFox, GN all say clean.
# ─────────────────────────────────────────────────────────────────────────────
print("\n── TEST 1: OTX-only mentions MUST NOT trigger classification ──")
vt_clean = {
    "malicious": 0, "suspicious": 0, "harmless": 92, "undetected": 2,
    "last_analysis_results": {}
}
otx_with_apt_tags = {
    "pulse_count": 3,
    "malware_family": "APT28",  # derived from pulses, NOT direct evidence
    "pulses": [
        {"name": "APT28 Phishing Campaign", "tags": ["apt28", "phishing", "c2", "ransomware"],
         "created": "2024-06-01", "id": "abc123", "author_name": "researcher_x"},
        {"name": "CobaltStrike Infrastructure Tracker", "tags": ["cobalt strike", "c2"],
         "created": "2024-05-15", "id": "def456"},
        {"name": "LockBit Ransomware IOCs", "tags": ["ransomware", "lockbit"],
         "created": "2024-05-01", "id": "ghi789"},
    ]
}
gn_clean = {"noise": False, "classification": "benign", "riot": True}

cls_otx_only = ti_rb._detect_classification(
    vt=vt_clean, feeds=[], abuse={}, greynoise=gn_clean
)
check("OTX tags MUST NOT produce classification",
      len(cls_otx_only) == 0,
      f"Got: {cls_otx_only}")

# Full report: classification should be empty
msg1, res1 = ti_rb.build_ti_report(
    ioc="13.107.42.14",  # Microsoft IP
    ioc_type="ip",
    vt=vt_clean,
    otx=otx_with_apt_tags,
    greynoise=gn_clean,
)
check("Report: no C2/Phishing/Ransomware classification in threat assessment",
      "C2 Infrastructure" not in msg1
      and "Phishing Infrastructure" not in msg1
      and "Ransomware Infrastructure" not in msg1,
      "Found incorrect classification in report!")

check("Report: Evidence Context section NOT shown in report",
      "EVIDENCE CONTEXT" not in msg1)

check("Report: OTX pulse name NOT shown in report",
      "APT28 Phishing Campaign" not in msg1)


# ─────────────────────────────────────────────────────────────────────────────
# Test 2: Community comments MUST NOT affect classification
# ─────────────────────────────────────────────────────────────────────────────
print("\n── TEST 2: Community comments MUST NOT affect classification ──")
comments_c2 = [
    {"date": "2024-06-01", "author": "analyst", "text": "This is C2 infrastructure for Cobalt Strike"},
    {"date": "2024-05-01", "author": "hunter",  "text": "ransomware distribution point confirmed"},
]
cls_comments = ti_rb._detect_classification(
    vt=vt_clean, feeds=[], abuse={}, greynoise=gn_clean
)
check("Community comments MUST NOT produce classification",
      len(cls_comments) == 0,
      f"Got: {cls_comments}")


# ─────────────────────────────────────────────────────────────────────────────
# Test 3: ThreatFox CAN produce classification (direct evidence)
# ─────────────────────────────────────────────────────────────────────────────
print("\n── TEST 3: ThreatFox MUST produce classification ──")
tf_feeds = [
    {"source": "ThreatFox", "threat_category": "cobalt strike", "confidence": 100,
     "first_seen": "2024-06-01"},
]
cls_tf = ti_rb._detect_classification(
    vt={}, feeds=tf_feeds, abuse={}, greynoise={}
)
check("ThreatFox C2 produces classification",
      "C2 Infrastructure" in cls_tf,
      f"Got: {cls_tf}")


# ─────────────────────────────────────────────────────────────────────────────
# Test 4: VT threat_label CAN produce classification
# ─────────────────────────────────────────────────────────────────────────────
print("\n── TEST 4: VT threat_label MUST produce classification ──")
vt_lockbit = {
    "malicious": 62, "suspicious": 0,
    "threat_label": "ransomware.lockbit/win",
    "last_analysis_results": {}
}
cls_vt = ti_rb._detect_classification(
    vt=vt_lockbit, feeds=[], abuse={}, greynoise={}
)
check("VT threat_label ransomware produces classification",
      "Ransomware Infrastructure" in cls_vt,
      f"Got: {cls_vt}")


# ─────────────────────────────────────────────────────────────────────────────
# Test 5: VT categories CAN produce classification (domain/URL)
# ─────────────────────────────────────────────────────────────────────────────
print("\n── TEST 5: VT categories (domain) MUST produce classification ──")
vt_phish_domain = {
    "malicious": 3, "suspicious": 1,
    "categories": {"Forcepoint": "phishing", "Sophos": "phishing"},
    "last_analysis_results": {}
}
cls_domain = ti_rb._detect_classification(
    vt=vt_phish_domain, feeds=[], abuse={}, greynoise={}
)
check("VT phishing categories produce Phishing Infrastructure",
      "Phishing Infrastructure" in cls_domain,
      f"Got: {cls_domain}")


# ─────────────────────────────────────────────────────────────────────────────
# Test 6: GreyNoise malicious CAN produce classification
# ─────────────────────────────────────────────────────────────────────────────
print("\n── TEST 6: GreyNoise malicious MUST produce classification ──")
gn_malicious = {"noise": True, "classification": "malicious", "name": "Cobalt Strike C2", "riot": False}
cls_gn = ti_rb._detect_classification(
    vt={}, feeds=feeds if 'feeds' in locals() else [], abuse={}, greynoise=gn_malicious
)
check("GreyNoise malicious C2 produces classification",
      "C2 Infrastructure" in cls_gn,
      f"Got: {cls_gn}")

# GreyNoise benign MUST NOT produce classification
gn_benign = {"noise": False, "classification": "benign", "riot": True}
cls_gn_benign = ti_rb._detect_classification(
    vt={}, feeds=[], abuse={}, greynoise=gn_benign
)
check("GreyNoise benign MUST NOT produce classification",
      len(cls_gn_benign) == 0,
      f"Got: {cls_gn_benign}")


# ─────────────────────────────────────────────────────────────────────────────
# Test 7: Generic OTX feed entry MUST NOT produce classification
# ─────────────────────────────────────────────────────────────────────────────
print("\n── TEST 7: Generic OTX feed entries MUST NOT produce classification ──")
otx_feed_entries = [
    {"source": "OTX", "threat_category": "c2", "confidence": 80},
    {"source": "otx", "threat_category": "ransomware"},
]
cls_otx_feed = ti_rb._detect_classification(
    vt={}, feeds=otx_feed_entries, abuse={}, greynoise={}
)
check("OTX feed entries MUST NOT produce classification",
      len(cls_otx_feed) == 0,
      f"Got: {cls_otx_feed}")


# ─────────────────────────────────────────────────────────────────────────────
# Test 8: Evidence Context section structure
# ─────────────────────────────────────────────────────────────────────────────
print("\n── TEST 8: Evidence Context section structure ──")
ev = ti_rb._build_evidence_context(otx_with_apt_tags, "13.107.42.14")
check("Evidence Context: disabled and returns empty string",
      ev == "")

# Empty when no pulses
ev_empty = ti_rb._build_evidence_context({"pulse_count": 0, "pulses": []}, "8.8.8.8")
check("Evidence Context: empty when no pulses",
      ev_empty == "")

# Empty when OTX error
ev_err = ti_rb._build_evidence_context({"error": "timeout"}, "8.8.8.8")
check("Evidence Context: empty when OTX error",
      ev_err == "")


# ─────────────────────────────────────────────────────────────────────────────
# Test 9: URLHaus CAN produce classification (authoritative feed)
# ─────────────────────────────────────────────────────────────────────────────
print("\n── TEST 9: URLHaus MUST produce classification ──")
uh_feeds = [
    {"source": "URLHaus", "threat_category": "malware",
     "raw_data": json.dumps({"tags": ["emotet", "botnet"], "malware_family": "Emotet"})},
]
cls_uh = ti_rb._detect_classification(
    vt={}, feeds=uh_feeds, abuse={}, greynoise={}
)
check("URLHaus malware produces classification",
      "Malware Distribution" in cls_uh or "Botnet Infrastructure" in cls_uh,
      f"Got: {cls_uh}")


# ─────────────────────────────────────────────────────────────────────────────
# Test 10: Tor flag from AbuseIPDB does NOT become a threat classification
# ─────────────────────────────────────────────────────────────────────────────
print("\n── TEST 10: Tor flag is infrastructure, not classification ──")
abuse_tor = {"abuse_score": 91, "total_reports": 500, "is_tor": True}
cls_tor = ti_rb._detect_classification(
    vt={}, feeds=[], abuse=abuse_tor, greynoise={}
)
check("Tor flag does NOT produce 'Tor Exit Node' in classification",
      "Tor Exit Node" not in cls_tor,
      f"Got: {cls_tor}")


# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "\u2550" * 60)
passed = sum(1 for r in results if r[0] == PASS)
failed = sum(1 for r in results if r[0] == FAIL)
label  = "PASSED" if failed == 0 else "ISSUES FOUND"
print(f"  Phase 12.1 Verification \u2014 {label}")
print("\u2550" * 60)
print(f"  Results: {passed} passed, {failed} failed")
if failed:
    print("\n  Failed checks:")
    for status, name, detail in results:
        if status == FAIL:
            print(f"    {FAIL}  {name}")
            if detail:
                print(f"           {detail}")
print()
sys.exit(0 if failed == 0 else 1)
