"""
tests/verify_phase15.py — Phase 15: VirusTotal Detection Transparency
Tests _build_vt_vendor_table() ensuring:
  - 0 detections  → empty string
  - 1 detection   → 1 vendor, no Summary
  - 2 detections  → 2 vendors
  - 9 detections  → all 9 shown
  - Mixed labels  → Summary counts shown
  - Noise vendors → filtered out
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ti_report_builder import _build_vt_vendor_table

_PASS = 0
_FAIL = 0


def check(name: str, condition: bool, extra: str = ""):
    global _PASS, _FAIL
    if condition:
        _PASS += 1
        print(f"  \u2705 PASS  {name}")
    else:
        _FAIL += 1
        msg = f"  \u274c FAIL  {name}"
        if extra:
            msg += f"\n       {extra}"
        print(msg)


def _make_vt(entries: list) -> dict:
    last = {}
    for vendor, cat, result in entries:
        last[vendor] = {"category": cat, "result": result}
    total = len(entries)
    mal   = sum(1 for _, c, _ in entries if c == "malicious")
    sus   = sum(1 for _, c, _ in entries if c == "suspicious")
    return {
        "malicious":  mal,
        "suspicious": sus,
        "harmless":   0,
        "undetected": max(0, 91 - total),
        "last_analysis_results": last,
    }


print("\n\u2550\u2550\u2550 PHASE 15: VirusTotal Detection Transparency \u2550\u2550\u2550\n")

# TEST 1: 0 detections
print("\u2500\u2500 TEST 1: 0 / 91 \u2500\u2500")
vt_0 = _make_vt([])
vt_0["last_analysis_results"]["Google"]  = {"category": "harmless",   "result": ""}
vt_0["last_analysis_results"]["Yandex"]  = {"category": "undetected", "result": ""}
out_0 = _build_vt_vendor_table(vt_0)
check("0 detections: empty string returned", out_0 == "")
check("0 detections: no Summary section",    "Summary" not in out_0)
check("0 detections: no Detections section", "Detections" not in out_0)

# TEST 2: 1 detection — single label type → no Summary
print("\n\u2500\u2500 TEST 2: 1 / 91 \u2500\u2500")
vt_1 = _make_vt([("Fortinet", "malicious", "Malware")])
out_1 = _build_vt_vendor_table(vt_1)
check("1 detection: non-empty output",                bool(out_1))
check("1 detection: Fortinet shown",                  "Fortinet" in out_1)
check("1 detection: Summary NOT shown (1 label type)","Summary" not in out_1)
check("1 detection: Detections section present",      "Detections" in out_1)
check("1 detection: exactly 1 bullet",                out_1.count("\u2022") == 1,
      f"Got {out_1.count(chr(8226))}")

# TEST 3: 2 detections
print("\n\u2500\u2500 TEST 3: 2 / 91 \u2500\u2500")
vt_2 = _make_vt([("Fortinet", "malicious", "Malware"), ("ADMINUSLabs", "malicious", "Malicious")])
out_2 = _build_vt_vendor_table(vt_2)
check("2 detections: Fortinet shown",    "Fortinet"    in out_2)
check("2 detections: ADMINUSLabs shown", "ADMINUSLabs" in out_2)
check("2 detections: exactly 2 bullets", out_2.count("\u2022") == 2,
      f"Got {out_2.count(chr(8226))}")

# TEST 4: 9 detections — all must appear
print("\n\u2500\u2500 TEST 4: 9 / 91 \u2500\u2500")
vendors_9 = [
    ("Fortinet",       "malicious",  "Malware"),
    ("ADMINUSLabs",    "malicious",  "Malicious"),
    ("BitDefender",    "phishing",   "Phishing"),
    ("Sophos",         "phishing",   "Phishing"),
    ("CRDF",           "malicious",  "Malicious"),
    ("AlphaMountain",  "suspicious", "Suspicious"),
    ("Kaspersky",      "malicious",  "Trojan.GenericKDZ"),
    ("ESET-NOD32",     "malicious",  "Win32/Agent.ABC"),
    ("Avast",          "malicious",  "Win32:Malware-gen"),
]
vt_9 = _make_vt(vendors_9)
out_9 = _build_vt_vendor_table(vt_9)
for v, _, _ in vendors_9:
    check(f"9 detections: {v} shown", v in out_9)
check("9 detections: exactly 9 bullets", out_9.count("\u2022") == 9,
      f"Got {out_9.count(chr(8226))}")

# TEST 5: Mixed labels → Summary shown
print("\n\u2500\u2500 TEST 5: Mixed label Summary counts \u2500\u2500")
mixed = [
    ("VendorA", "malicious",  "Malicious"),
    ("VendorB", "malicious",  "Malicious"),
    ("VendorC", "malware",    "Malware"),
    ("VendorD", "phishing",   "Phishing"),
    ("VendorE", "phishing",   "Phishing"),
    ("VendorF", "phishing",   "Phishing"),
    ("VendorG", "suspicious", "Suspicious"),
]
vt_mix = _make_vt(mixed)
out_mix = _build_vt_vendor_table(vt_mix)
check("Mixed: Summary present",    "Summary"    in out_mix)
check("Mixed: Detections present", "Detections" in out_mix)
for v, _, _ in mixed:
    check(f"Mixed: {v} listed", v in out_mix)
check("Mixed: 'Malicious' label shown",  "Malicious"  in out_mix)
check("Mixed: 'Malware' label shown",    "Malware"    in out_mix)
check("Mixed: 'Phishing' label shown",   "Phishing"   in out_mix)
check("Mixed: 'Suspicious' label shown", "Suspicious" in out_mix)

# TEST 6: Specific threat name display
print("\n\u2500\u2500 TEST 6: Specific threat name display \u2500\u2500")
specific = [("Kaspersky", "malicious", "Trojan.GenericKDZ"), ("ESET", "malicious", "Malicious")]
vt_spec = _make_vt(specific)
out_spec = _build_vt_vendor_table(vt_spec)
check("Specific: Kaspersky Trojan.GenericKDZ shown", "Trojan.GenericKDZ" in out_spec)
check("Specific: ESET normalized to Malicious",      "Malicious" in out_spec)

# TEST 7: Noise vendors must NOT appear
print("\n\u2500\u2500 TEST 7: Noise vendors filtered out \u2500\u2500")
noisy = [
    ("Fortinet",  "malicious",  "Malware"),
    ("Google",    "harmless",   ""),
    ("Yandex",    "undetected", ""),
    ("Microsoft", "clean",      ""),
]
vt_noisy = _make_vt(noisy)
out_noisy = _build_vt_vendor_table(vt_noisy)
check("Noise: Fortinet shown",      "Fortinet"  in out_noisy)
check("Noise: Google NOT shown",    "Google"    not in out_noisy)
check("Noise: Yandex NOT shown",    "Yandex"    not in out_noisy)
check("Noise: Microsoft NOT shown", "Microsoft" not in out_noisy)

print(f"""
\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
  Phase 15 VT Detection Transparency \u2014 {'PASSED' if _FAIL == 0 else 'ISSUES FOUND'}
\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
  Results: {_PASS} passed, {_FAIL} failed
""")

sys.exit(0 if _FAIL == 0 else 1)
