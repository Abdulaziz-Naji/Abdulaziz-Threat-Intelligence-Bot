"""
dfir_engine.py - Autonomous DFIR Execution Engine v2.0

Behaves as a Senior DFIR Investigator and Incident Responder.

AUTOMATIC ANALYSIS PIPELINE:
  File Upload → Type Detection → Forensic Routing → Deep Analysis
  → IOC Extraction → TI Enrichment → Cross-Evidence Correlation
  → Attack Reconstruction → Hypothesis → 12-Section Report

Supported evidence modules (auto-routed, no command required):
  - IMAGE:    EXIF, GPS, steganography indicators, OCR hints
  - PCAP:     TCP/UDP streams, DNS, HTTP, beaconing, C2 patterns
  - PE/EXE:   Headers, sections, strings, API calls, import analysis
  - ELF:      Linux binary analysis, strings, symbols
  - OFFICE:   OLE macros, VBA, embedded objects, URLs (DOCX/XLSX/DOC)
  - MEMORY:   String heuristics, process names, credential artifacts
  - DISK:     Heuristic partition scan, artifact strings
  - SCRIPT:   Obfuscation, suspicious API, C2 URLs
  - GENERIC:  IOC extraction, entropy, threat intelligence
  - EMAIL:    Header chain, auth failures, originating IP
"""
from __future__ import annotations

import io
import re
import json
import math
import struct
import hashlib
import logging
import subprocess
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

logger = logging.getLogger(__name__)


# ─── MITRE ATT&CK Technique Map ───────────────────────────────────────────────

MITRE_SIGNATURES: dict[str, list[str]] = {
    # Execution
    "powershell":         ["T1059.001 – PowerShell"],
    "cmd.exe":            ["T1059.003 – Windows Command Shell"],
    "wscript":            ["T1059.005 – Visual Basic"],
    "cscript":            ["T1059.005 – Visual Basic"],
    "mshta":              ["T1218.005 – Mshta"],
    "rundll32":           ["T1218.011 – Rundll32"],
    "regsvr32":           ["T1218.010 – Regsvr32"],
    # Persistence
    "hkcu\\software\\microsoft\\windows\\currentversion\\run": ["T1547.001 – Registry Run Keys"],
    "scheduled task":     ["T1053.005 – Scheduled Task"],
    "startup folder":     ["T1547.001 – Startup Folder"],
    # Privilege Escalation
    "mimikatz":           ["T1003.001 – LSASS Memory Dump"],
    "sekurlsa":           ["T1003.001 – LSASS Memory Dump"],
    "privilege::debug":   ["T1134 – Access Token Manipulation"],
    # Defense Evasion
    "base64":             ["T1027 – Obfuscated Files or Information"],
    "vba macro":          ["T1137.001 – Office Template Macros"],
    "autoopen":           ["T1137.001 – Office VBA AutoOpen"],
    "/js":                ["T1059.007 – JavaScript (PDF)"],
    "/javascript":        ["T1059.007 – Embedded JavaScript"],
    "openaction":         ["T1204 – User Execution (Auto-Open PDF)"],
    # C2 / Exfiltration
    "beacon":             ["T1071.001 – Web Protocols C2", "T1041 – Exfiltration over C2"],
    "cobalt strike":      ["T1071.001 – Cobalt Strike C2"],
    "metasploit":         ["T1071 – Application Layer Protocol"],
    # Discovery
    "whoami":             ["T1033 – System Owner/User Discovery"],
    "ipconfig":           ["T1016 – System Network Configuration Discovery"],
    "netstat":            ["T1049 – System Network Connections Discovery"],
    "net user":           ["T1087.001 – Local Account Discovery"],
    "arp -a":             ["T1018 – Remote System Discovery"],
    # Lateral Movement
    "psexec":             ["T1021.002 – SMB/Windows Admin Shares"],
    "wmic":               ["T1047 – Windows Management Instrumentation"],
    "pass-the-hash":      ["T1550.002 – Pass the Hash"],
    # Impact
    ".locky":             ["T1486 – Data Encrypted for Impact (Ransomware)"],
    ".wannacry":          ["T1486 – Data Encrypted for Impact (WannaCry)"],
    "vssadmin delete":    ["T1490 – Inhibit System Recovery"],
    "bcdedit":            ["T1490 – Inhibit System Recovery"],
}


def map_mitre_techniques(text: str) -> list[str]:
    """Scan arbitrary text and return matched MITRE ATT&CK techniques."""
    text_lower = text.lower()
    found: set[str] = set()
    for keyword, techniques in MITRE_SIGNATURES.items():
        if keyword.lower() in text_lower:
            for t in techniques:
                found.add(t)
    return sorted(found)


# ─── DFIR Finding dataclass ───────────────────────────────────────────────────

@dataclass
class DFIRFinding:
    """A single forensic finding."""
    timestamp: str
    category: str      # FILE | NETWORK | MEMORY | EMAIL | IOC
    severity: str      # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str
    detail: str
    evidence: str = ""
    mitre: list[str] = field(default_factory=list)
    reasoning: str = ""
    confidence: int = 100
    alternative_explanation: str = ""
    recommended_action: str = ""
    supporting_artifacts: list[str] = field(default_factory=list)
    related_iocs: list[str] = field(default_factory=list)
    ti_references: list[str] = field(default_factory=list)

    @property
    def severity_emoji(self) -> str:
        return {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}.get(self.severity, "⚪")


@dataclass
class DFIRReport:
    """Complete DFIR Investigation Report — 12-section autonomous output."""
    case_id: str
    evidence_type: str
    evidence_name: str
    investigator: str = "Autonomous DFIR Engine v2.0"
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: str = ""

    # Core Investigator Narrative
    what_happened: str = ""
    when_happened: str = ""
    how_happened: str = ""
    initial_access: str = ""
    attacker_actions: list[str] = field(default_factory=list)
    affected_systems: list[str] = field(default_factory=list)
    evidence_summary: list[str] = field(default_factory=list)
    attack_timeline: list[dict] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    containment: list[str] = field(default_factory=list)

    # Findings
    findings: list[DFIRFinding] = field(default_factory=list)
    extracted_iocs: dict = field(default_factory=lambda: {
        "ips": [], "domains": [], "urls": [], "emails": [],
        "hashes": [], "filenames": [], "usernames": []
    })
    risk_score: int = 0
    verdict: str = "UNKNOWN"

    # ── NEW: Autonomous Engine Fields ─────────────────────────────────────────
    # Hypothesis & Confidence
    hypothesis: dict = field(default_factory=lambda: {
        "primary": "",
        "attack_type": "",
        "malware_family": "",
        "confidence": 0,
        "reasoning": []
    })
    # Attack Kill Chain (MITRE phases)
    attack_chain: list[dict] = field(default_factory=list)
    # Cross-evidence correlation graph
    correlation_graph: dict = field(default_factory=dict)
    # TI enrichment results keyed by IOC
    ti_enrichment: dict = field(default_factory=dict)
    # Entropy score of file
    entropy: float = 0.0
    # File type as detected
    detected_type: str = ""
    # Structured evidence extracted from the file
    extracted_evidence: dict = field(default_factory=lambda: {
        "ips": [], "domains": [], "urls": [], "emails": [], "hashes": [],
        "processes": [], "network_flows": [], "credentials": [], "persistence": [],
        "fs_artifacts": [], "registry_keys": [], "api_calls": [], "metadata": [],
        "vba_macros": [], "obfuscation": [], "others": []
    })
    # Advanced network traffic intelligence analytics
    # Advanced network traffic intelligence analytics
    network_analytics: dict = field(default_factory=lambda: {
        "top_talkers": [],       # list of dicts with traffic flow stats
        "port_breakdown": {},     # port -> count
        "beaconing_sessions": [], # dict of beacon sessions
        "credentials": []         # list of credentials
    })
    analyst_mode_logs: list[str] = field(default_factory=list)


    def add_finding(self, category: str, severity: str, title: str, detail: str,
                    evidence: str = "", mitre: list[str] = None):
        # 1. Validation: Is there actual evidence?
        if not evidence or not evidence.strip() or evidence == "None":
            # Suppress if no evidence
            self.analyst_mode_logs.append(f"Finding suppressed: '{title}' lacks actual evidence.")
            return

        # 2. Dynamic reasoning, confidence, and alternative explanation builder
        conf = 85
        reasoning = ""
        alt_exp = ""
        rec_action = ""
        mitre_list = mitre or []

        # Analyze keywords in title or detail
        t_lower = title.lower()
        d_lower = detail.lower()

        if "entropy" in t_lower or "high entropy" in t_lower:
            conf = 55
            reasoning = "High Shannon entropy indicates lack of file compression or structured randomness, typical for packed, encrypted, or highly compressed binary assets."
            alt_exp = "Normal compressed document (zip/docx/pdf), media resources (JPEG/PNG/MP3), or obfuscated compiled code."
            rec_action = "Compare file strings, check certificates, and review imports."
            # Remove T1027 and T1486 for raw entropy findings
            mitre_list = [t for t in mitre_list if "T1027" not in t and "T1486" not in t]
            self.analyst_mode_logs.append("MITRE mapping skipped for T1027/T1486 on raw entropy finding.")
            self.analyst_mode_logs.append("High entropy finding flagged. Confidence reduced to 55% (heuristic only).")

        elif "virustotal" in t_lower:
            if "no detections" in t_lower or "clean" in t_lower:
                conf = 15
                reasoning = "VirusTotal security vendors reported zero malicious detections for this file hash."
                alt_exp = "BENIGN"
                rec_action = "Allow file execution."
            else:
                conf = 95
                reasoning = "Security vendors on VirusTotal flagged this file hash against known malicious signature databases."
                alt_exp = "Security testing tool (like EICAR), signature collision, or legacy engine false positive."
                rec_action = "Quarantine the file and investigate endpoint execution."

        elif "gps" in t_lower or "location" in t_lower:
            conf = 90
            reasoning = "Geographical coordinates were found in the EXIF metadata, mapping directly to physical locations."
            alt_exp = "Default camera tagging configurations by the owner or user."
            rec_action = "Sanitize metadata before file sharing."
            mitre_list = [t for t in mitre_list if "T1027" not in t]

        elif "manipulated" in t_lower or "edited" in t_lower or "software" in t_lower:
            conf = 50
            reasoning = "Image metadata registers editing software tools (e.g. Photoshop, GIMP, Canva)."
            alt_exp = "Standard design work, image cropping, or resizing by a content creator."
            rec_action = "Review image content manually for authenticity."
            mitre_list = [t for t in mitre_list if "T1027" not in t and "T1547" not in t and "T1037" not in t and "T1543" not in t]
            self.analyst_mode_logs.append("MITRE mapping skipped for Photoshop/camera metadata.")

        elif "macro" in t_lower or "vba" in t_lower:
            conf = 75
            reasoning = "VBA macro code or document launch triggers are embedded in the Office document structure."
            alt_exp = "Legitimate administrative macros or interactive forms."
            rec_action = "Extract macro source code and analyze for execution payloads."

        elif "javascript" in t_lower or "js in pdf" in t_lower or "openaction" in t_lower:
            conf = 75
            reasoning = "PDF contains scripting streams or automatic execution markers (/OpenAction)."
            alt_exp = "Benign interactive forms, dynamic calculations, or print dialog triggers."
            rec_action = "Analyze PDF objects manually using pdf-parser or custom script."

        elif "steganography" in t_lower or "appended" in t_lower or "embedded" in t_lower:
            conf = 90
            reasoning = "Discovered binary signature matches or raw bytes appended past the EOI/IEND markers, indicating hidden payloads."
            alt_exp = "Trailing comments, thumbnail assets, or multipart image streams."
            rec_action = "Extract hidden offsets and analyze the carved file."

        elif "carved" in t_lower or "network ioc" in t_lower:
            conf = 65
            reasoning = "Plain text carving extracted IP/URL strings from generic file byte chunks."
            alt_exp = "References to update servers, documentation links, or default software URLs."
            rec_action = "Enrich extracted domains and check firewall traffic logs."

        elif "c2" in t_lower or "beacon" in t_lower or "traffic" in t_lower:
            conf = 85
            reasoning = "Outbound network packet traffic matches periodic interval profiles (beaconing) or C2 destinations."
            alt_exp = "API polling, web-socket keep-alives, or standard telemetry channels."
            rec_action = "Block destination IP/domain at perimeter and contain host."

        elif "credential" in t_lower or "cleartext" in t_lower:
            conf = 95
            reasoning = "Sensitive access data (username, password, AWS keys, JWTs) observed in plain text logs/transfers."
            alt_exp = "Developer debug output or testing credentials."
            rec_action = "Revoke compromise credentials and rotate keys immediately."

        else:
            conf = 70
            reasoning = "Forensic inspection identified suspicious patterns in the analyzed resource."
            alt_exp = "Benign administrative tool, standard debugging data, or developer remnants."
            rec_action = "Perform deeper manual triage on target system."

        # Apply confidence thresholds:
        if conf < 60:
            severity = "INFO"
            title_prefix = "[Informational]"
            self.analyst_mode_logs.append(f"Finding '{title}' demoted to INFO (confidence {conf}% < 60%).")
        elif conf <= 80:
            severity = "MEDIUM" if severity not in ("LOW", "MEDIUM") else severity
            title_prefix = "[Suspicious]"
        else:
            severity = "HIGH" if severity not in ("HIGH", "CRITICAL") else severity
            title_prefix = "[Confirmed]"

        # Ensure title prefix is only added once
        clean_title = title
        for prefix in ("[Confirmed]", "[Suspicious]", "[Informational]"):
            if clean_title.startswith(prefix):
                clean_title = clean_title[len(prefix):].strip()
        final_title = f"{title_prefix} {clean_title}"

        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # Supporting artifacts & related IOCs
        supporting_arts = [self.evidence_name]
        related_iocs_list = []
        for ioc_val in (self.extracted_iocs.get("ips", []) + self.extracted_iocs.get("domains", []) + self.extracted_iocs.get("urls", [])):
            if ioc_val in detail or ioc_val in evidence:
                related_iocs_list.append(ioc_val)

        self.findings.append(DFIRFinding(
            timestamp=ts,
            category=category,
            severity=severity,
            title=final_title,
            detail=detail,
            evidence=evidence,
            mitre=mitre_list,
            reasoning=reasoning,
            confidence=conf,
            alternative_explanation=alt_exp,
            recommended_action=rec_action,
            supporting_artifacts=supporting_arts,
            related_iocs=list(set(related_iocs_list)),
            ti_references=["VirusTotal", "AbuseIPDB", "OTX"] if any(x in t_lower or x in d_lower for x in ("virustotal", "abuse", "otx")) else []
        ))

        # Track MITRE techniques globally
        for t in mitre_list:
            if t not in self.mitre_techniques:
                self.mitre_techniques.append(t)
        # Raise risk score
        severity_weight = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5, "INFO": 0}
        self.risk_score = min(self.risk_score + severity_weight.get(severity, 0), 100)

    def finalize(self):
        self.completed_at = datetime.now(timezone.utc).isoformat()
        
        # JPEG/PNG high entropy suppression
        image_types = ("png", "jpg", "jpeg", "gif", "webp", "tiff", "bmp")
        if (self.detected_type or "").lower() in image_types or any(self.evidence_name.lower().endswith(ext) for ext in image_types):
            # Check if there's any stego or actual malicious indicators
            stego_or_malicious = False
            for f in self.findings:
                f_title = f.title.lower()
                # Check for other indicators
                if any(x in f_title for x in ("steganography", "embedded", "appended", "hidden", "ocr", "qr", "flag", "credential", "virustotal", "malicious", "threat")):
                    if "no detections" not in f_title:
                        stego_or_malicious = True
            
            # If no stego or actual malicious indicators, remove any High Entropy findings
            entropy_findings = [f for f in self.findings if "entropy" in f.title.lower()]
            if entropy_findings and not stego_or_malicious:
                self.analyst_mode_logs.append("High entropy finding suppressed: JPEG/PNG image compression naturally produces high entropy and no other stego/malicious indicators were found.")
                self.findings = [f for f in self.findings if f not in entropy_findings]

        # Recalculate risk score
        severity_weight = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5, "INFO": 0}
        self.risk_score = 0
        for f in self.findings:
            self.risk_score = min(self.risk_score + severity_weight.get(f.severity, 0), 100)

        # Set verdict from risk score
        if self.risk_score >= 75:
            self.verdict = "CONFIRMED THREAT"
        elif self.risk_score >= 40:
            self.verdict = "MALICIOUS"
        elif self.risk_score >= 15:
            self.verdict = "SUSPICIOUS"
        else:
            self.verdict = "BENIGN"


# ─── IOC Extractor ────────────────────────────────────────────────────────────

_RE_IP   = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
_RE_DOM  = re.compile(r'\b(?:[a-z0-9\-]+\.)+(?:com|net|org|io|ru|cn|de|uk|fr|info|xyz|top|cc|pw|tk|ml|ga)\b', re.I)
_RE_URL  = re.compile(r'https?://[^\s<>"\']{4,200}')
_RE_MAIL = re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b')
_RE_MD5  = re.compile(r'\b[0-9a-fA-F]{32}\b')
_RE_SHA1 = re.compile(r'\b[0-9a-fA-F]{40}\b')
_RE_SHA256 = re.compile(r'\b[0-9a-fA-F]{64}\b')

# Private/reserved IP ranges to exclude from extracted IOCs
_PRIVATE_PREFIXES = (
    "127.", "0.", "10.", "192.168.", "172.16.", "172.17.", "172.18.",
    "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
    "172.31.", "255.", "224."
)


def extract_iocs_from_text(text: str) -> dict:
    """Extract all IOC types from arbitrary text."""
    ips      = [ip for ip in _RE_IP.findall(text)
                if not any(ip.startswith(p) for p in _PRIVATE_PREFIXES)]
    domains  = list(set(_RE_DOM.findall(text)))
    urls     = list(set(_RE_URL.findall(text)))
    emails   = list(set(_RE_MAIL.findall(text)))
    sha256s  = list(set(_RE_SHA256.findall(text)))
    sha1s    = [h for h in set(_RE_SHA1.findall(text)) if h not in sha256s]
    md5s     = [h for h in set(_RE_MD5.findall(text))
                if h not in sha256s and h not in sha1s]

    return {
        "ips":      list(set(ips))[:20],
        "domains":  domains[:20],
        "urls":     urls[:20],
        "emails":   emails[:10],
        "hashes":   (sha256s + sha1s + md5s)[:20],
        "filenames": [],
        "usernames": []
    }


# ─── File DFIR Analyzer ───────────────────────────────────────────────────────

def analyze_file_dfir(
    file_bytes: bytes,
    filename: str,
    file_type: str,
    metadata: dict,
    anomalies: list[str],
    vt_result: dict,
    mb_result: dict,
) -> DFIRReport:
    """
    Produce a full DFIR investigation report from file artifacts.
    Acts as a Senior DFIR Investigator interpreting all forensic signals.
    """
    case_id = hashlib.md5(file_bytes[:512]).hexdigest()[:8].upper()
    report = DFIRReport(
        case_id=case_id,
        evidence_type="FILE",
        evidence_name=filename,
    )

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # ── Hash fingerprinting ───────────────────────────────────────────────────
    sha256 = hashlib.sha256(file_bytes).hexdigest()
    md5    = hashlib.md5(file_bytes).hexdigest()
    sha1   = hashlib.sha1(file_bytes).hexdigest()

    report.evidence_summary.append(f"File: {filename} ({len(file_bytes)/1024:.1f} KB, {file_type.upper()})")
    report.evidence_summary.append(f"SHA-256: {sha256}")
    report.evidence_summary.append(f"MD5:     {md5}")

    # ── VirusTotal findings ───────────────────────────────────────────────────
    vt_mal = vt_result.get("malicious", 0) if vt_result and "error" not in vt_result else 0
    vt_total = (vt_result.get("harmless", 0) + vt_result.get("undetected", 0) +
                vt_result.get("suspicious", 0) + vt_mal) if vt_result and "error" not in vt_result else 0
    vt_label = vt_result.get("threat_label", "") if vt_result else ""

    if vt_mal > 0:
        severity = "CRITICAL" if vt_mal >= 10 else "HIGH" if vt_mal >= 3 else "MEDIUM"
        report.add_finding(
            category="FILE",
            severity=severity,
            title=f"VirusTotal: {vt_mal}/{vt_total} Engines Detected Malware",
            detail=f"Threat label: {vt_label or 'Unknown'}. File is confirmed malicious by {vt_mal} AV engines.",
            evidence=f"SHA-256: {sha256[:32]}…",
            mitre=["T1204.002 – Malicious File"] if vt_mal > 0 else []
        )
        report.initial_access = "Malicious file delivery (T1204.002 – User Execution: Malicious File)"
        report.what_happened = f"A malicious file was identified: {filename}. It was flagged by {vt_mal}/{vt_total} antivirus engines on VirusTotal with threat classification: {vt_label or 'Unclassified'}."

    elif vt_total > 0:
        report.add_finding("FILE", "INFO", "VirusTotal: No Detections",
                           f"Scanned by {vt_total} engines — no malicious detections found.", evidence=f"MD5: {md5}")
        report.what_happened = f"File '{filename}' was scanned across {vt_total} AV engines with no detections. File appears benign based on signature analysis."

    # ── MalwareBazaar ─────────────────────────────────────────────────────────
    if mb_result and mb_result.get("found"):
        sig = mb_result.get("signature", "Unknown")
        ftype_mb = mb_result.get("file_type", "Unknown")
        first_seen = mb_result.get("first_seen", "Unknown")
        report.add_finding(
            category="FILE", severity="CRITICAL",
            title=f"MalwareBazaar: Known Malware — {sig}",
            detail=f"File matches a known malware sample in MalwareBazaar database. "
                   f"Signature: {sig}, Type: {ftype_mb}, First Seen: {first_seen}.",
            evidence=f"SHA-256: {sha256[:32]}…",
            mitre=["T1204.002 – Malicious File"]
        )
        report.evidence_summary.append(f"MalwareBazaar: MATCHED — {sig} (First seen: {first_seen})")
        report.what_happened = f"File '{filename}' is a known malware sample. Signature: {sig}. " \
                               f"First observed in the wild: {first_seen}."

    # ── Type-specific forensics (auto-routed) ────────────────────────────────
    report.detected_type = file_type

    extract_evidence_dfir(report, file_bytes, filename, file_type, metadata, anomalies, sha256)
    analyze_evidence_dfir(report)

    # ── Scan full file for IOCs ───────────────────────────────────────────────
    try:
        raw_text = file_bytes.decode("utf-8", errors="ignore")
        iocs = extract_iocs_from_text(raw_text)
        report.extracted_iocs = iocs

        total_iocs = sum(len(v) for v in iocs.values())
        if total_iocs > 0:
            ioc_summary_parts = []
            if iocs["ips"]:      ioc_summary_parts.append(f"{len(iocs['ips'])} IPs")
            if iocs["domains"]:  ioc_summary_parts.append(f"{len(iocs['domains'])} domains")
            if iocs["urls"]:     ioc_summary_parts.append(f"{len(iocs['urls'])} URLs")
            if iocs["emails"]:   ioc_summary_parts.append(f"{len(iocs['emails'])} emails")
            if iocs["hashes"]:   ioc_summary_parts.append(f"{len(iocs['hashes'])} hashes")

            report.add_finding(
                category="FILE", severity="HIGH" if total_iocs >= 5 else "MEDIUM",
                title=f"Embedded IOCs Detected: {total_iocs} Indicators",
                detail=f"Extracted from file content: {', '.join(ioc_summary_parts)}. "
                       "These should be correlated against threat intelligence feeds.",
                evidence=f"Sample IPs: {', '.join(iocs['ips'][:3]) or 'None'} | "
                         f"Domains: {', '.join(iocs['domains'][:3]) or 'None'}",
                mitre=map_mitre_techniques(raw_text[:2000])
            )
    except Exception as e:
        logger.debug(f"IOC extraction from file: {e}")

    # ── MITRE mapping from anomalies ─────────────────────────────────────────
    anomaly_text = " ".join(anomalies).lower()
    extra_mitre = map_mitre_techniques(anomaly_text)
    for t in extra_mitre:
        if t not in report.mitre_techniques:
            report.mitre_techniques.append(t)

    # ── Entropy ───────────────────────────────────────────────────────────────
    report.entropy = _calc_entropy(file_bytes)
    if report.entropy > 7.2:
        report.add_finding(
            category="FILE", severity="MEDIUM",
            title=f"High Entropy Detected ({report.entropy:.2f}/8.0) — Packed or Encrypted",
            detail="High Shannon entropy indicates the file may be packed, encrypted, or obfuscated. "
                   "Malware commonly uses packers (UPX, Themida) to evade signature detection.",
            mitre=["T1027 – Obfuscated Files or Information"]
        )

    # ── Timeline ──────────────────────────────────────────────────────────────
    if not report.attack_timeline:
        report.attack_timeline = []
    report.attack_timeline.insert(0, {"time": "T+0", "event": f"File '{filename}' received for autonomous DFIR analysis"})
    report.attack_timeline.append({"time": now_str, "event": f"Analysis complete — {len(report.findings)} findings, risk {report.risk_score}/100"})
    if mb_result and mb_result.get("found"):
        first_seen = mb_result.get("first_seen", "Unknown")
        report.attack_timeline.insert(0, {
            "time": first_seen,
            "event": f"First seen in the wild (MalwareBazaar) — {mb_result.get('signature', 'Unknown')}",
        })
    # Sort timeline events (put T+0 entries at top, dated entries in order)
    _sort_timeline(report)

    # ── Investigator Narrative ────────────────────────────────────────────────
    report.when_happened = now_str
    if not report.what_happened:
        report.what_happened = (
            f"File '{filename}' automatically submitted to the DFIR Execution Engine. "
            f"Type: {file_type.upper()}, Size: {len(file_bytes)/1024:.1f} KB, "
            f"Entropy: {report.entropy:.2f}/8.0."
        )

    report.how_happened = _infer_delivery_method(file_type, anomalies, mb_result)

    # ── Attacker Actions ─────────────────────────────────────────────────────
    report.attacker_actions = _infer_attacker_actions(file_type, report.findings,
                                                       report.extracted_iocs, anomalies)

    # ── Affected Systems ─────────────────────────────────────────────────────
    report.affected_systems = _infer_affected_systems(file_type, anomalies)

    # ── Next Steps ────────────────────────────────────────────────────────────
    report.next_steps = _generate_next_steps(report)

    # ── Containment ──────────────────────────────────────────────────────────
    report.containment = _generate_containment(report)

    # ── Correlation Engine ────────────────────────────────────────────────────
    correlate_evidence(report)

    # ── Attack Chain (Kill Chain Reconstruction) ──────────────────────────────
    report.attack_chain = reconstruct_attack_chain(report)

    # ── Hypothesis Engine ─────────────────────────────────────────────────────
    report.hypothesis = generate_hypothesis(report)

    report.finalize()
    return report


# ─── Type-specific analyzers ──────────────────────────────────────────────────

# ─── Narrative Inference Helpers ──────────────────────────────────────────────

def _infer_delivery_method(file_type: str, anomalies: list, mb_result: dict) -> str:
    delivery = mb_result.get("delivery_method", "") if mb_result and mb_result.get("found") else ""
    if delivery:
        return f"Delivery method (from MalwareBazaar): {delivery}"

    delivery_map = {
        "pdf": "Likely delivered via spearphishing email as a malicious PDF attachment (T1566.001). "
               "PDF exploits typically target unpatched Adobe Acrobat Reader or browser PDF plugins.",
        "zip": "Likely delivered as a password-protected email attachment or drive-by download. "
               "ZIP containers bypass email gateway content inspection.",
        "apk": "Likely distributed via sideloading outside Google Play Store — malicious APK links "
               "sent via SMS, email, or social engineering.",
        "doc": "Likely delivered via spearphishing email with macro-enabled document (T1566.001). "
               "Macro execution initiates the infection chain.",
    }
    return delivery_map.get(file_type,
           f"File type ({file_type.upper()}) suggests delivery via phishing, drive-by download, or insider threat.")


def _infer_attacker_actions(file_type: str, findings: list, iocs: dict, anomalies: list) -> list[str]:
    actions = []
    for f in findings:
        if f.severity in ("CRITICAL", "HIGH"):
            actions.append(f"[{f.severity}] {f.title}")

    if iocs.get("ips"):
        actions.append(f"Beaconing / C2 communication to {len(iocs['ips'])} IP address(es): "
                       f"{', '.join(iocs['ips'][:3])}")
    if iocs.get("domains"):
        actions.append(f"DNS resolution of {len(iocs['domains'])} domain(s): "
                       f"{', '.join(iocs['domains'][:3])}")
    if not actions:
        actions.append("No high-confidence attacker actions identified — file may be benign or obfuscated.")
    return actions


def _infer_affected_systems(file_type: str, anomalies: list) -> list[str]:
    system_map = {
        "pdf":  ["Endpoint running unpatched PDF reader", "Email gateway (if delivered via email)"],
        "zip":  ["Endpoint receiving email attachments", "File sharing server"],
        "apk":  ["Android mobile device (sideloaded application)", "MDM-managed mobile fleet"],
        "png":  ["System that processed the image file", "Web application (if uploaded)"],
        "jpg":  ["System that processed the image file"],
    }
    return system_map.get(file_type, ["Endpoint where file was executed", "Network egress points"])


def _generate_next_steps(report: DFIRReport) -> list[str]:
    steps = []
    iocs = report.extracted_iocs

    if iocs.get("hashes"):
        steps.append(f"✅ Submit {len(iocs['hashes'])} extracted hash(es) for full threat intelligence lookup")
    if iocs.get("ips"):
        steps.append(f"✅ Investigate {len(iocs['ips'])} extracted IP(s) in AbuseIPDB, VirusTotal, and OTX")
    if iocs.get("domains"):
        steps.append(f"✅ Perform DNS + WHOIS analysis on {len(iocs['domains'])} extracted domain(s)")
    if iocs.get("urls"):
        steps.append(f"✅ Submit {len(iocs['urls'])} extracted URL(s) to phishing analysis engine")

    if report.risk_score >= 40:
        steps.extend([
            "✅ Isolate affected systems from network immediately",
            "✅ Collect full memory dump from affected endpoints (Volatility3 analysis)",
            "✅ Review EDR/AV logs for the last 72 hours on affected systems",
            "✅ Search SIEM for lateral movement indicators",
            "✅ Check email gateway logs for sender/attachment pattern",
        ])
    elif report.risk_score >= 15:
        steps.extend([
            "✅ Monitor affected systems for anomalous network connections",
            "✅ Review process creation and network connection events",
            "✅ Check for persistence mechanisms (startup, registry, scheduled tasks)",
        ])
    else:
        steps.append("✅ File appears benign — document findings and close case if no other indicators")

    if report.mitre_techniques:
        steps.append(f"✅ Review MITRE ATT&CK Navigator for defensive mitigations: "
                     f"{', '.join(report.mitre_techniques[:3])}")
    return steps


def _generate_containment(report: DFIRReport) -> list[str]:
    containment = []
    if report.risk_score >= 75:
        containment = [
            "🚫 IMMEDIATE: Isolate affected systems from the network",
            "🚫 IMMEDIATE: Block all extracted IPs and domains at the firewall/proxy",
            "🚫 IMMEDIATE: Revoke credentials of potentially compromised accounts",
            "🚫 IMMEDIATE: Disable the malicious file hash at endpoint security platform",
            "🚫 IMMEDIATE: Escalate to CIRT (Computer Incident Response Team)",
            "🚫 Preserve disk images and memory dumps for forensic analysis",
            "🚫 Begin notification process per incident response policy",
        ]
    elif report.risk_score >= 40:
        containment = [
            "⚠️ HIGH PRIORITY: Quarantine affected endpoints",
            "⚠️ HIGH PRIORITY: Block extracted IOCs at perimeter",
            "⚠️ Scan all similar file types received in the last 30 days",
            "⚠️ Review endpoint protection logs for related detections",
            "⚠️ Alert security team for enhanced monitoring",
        ]
    elif report.risk_score >= 15:
        containment = [
            "👁 MONITOR: Place file hash on watchlist for recurrence",
            "👁 MONITOR: Track any network connections to extracted IOCs",
            "👁 Document findings for threat intelligence enrichment",
        ]
    else:
        containment = [
            "✅ No immediate containment required",
            "✅ Add file hash to enrichment database for future reference",
        ]
    return containment


# ─── Email Header DFIR ────────────────────────────────────────────────────────

def analyze_email_header_dfir(header_text: str, parsed_hops: list, originating_ip: str) -> DFIRReport:
    """Produce a DFIR report for email header investigation."""
    case_id = hashlib.md5(header_text[:256].encode()).hexdigest()[:8].upper()
    report = DFIRReport(
        case_id=case_id,
        evidence_type="EMAIL",
        evidence_name="Email Header Analysis",
    )
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Extract IOCs
    iocs = extract_iocs_from_text(header_text)
    report.extracted_iocs = iocs

    if originating_ip:
        report.evidence_summary.append(f"Originating IP: {originating_ip}")
        if originating_ip not in iocs["ips"]:
            iocs["ips"].insert(0, originating_ip)

    # Hop analysis
    if parsed_hops:
        report.evidence_summary.append(f"Email routing: {len(parsed_hops)} hops traced")
        for hop in parsed_hops[:5]:
            report.attack_timeline.append({
                "time": hop.get("timestamp", "Unknown"),
                "event": f"Email relay: {hop.get('from', '?')} → {hop.get('by', '?')}"
            })

    # Spoof detection
    spf_fail = "spf=fail" in header_text.lower()
    dkim_fail = "dkim=fail" in header_text.lower()
    dmarc_fail = "dmarc=fail" in header_text.lower()

    if spf_fail or dkim_fail or dmarc_fail:
        checks = [x for x, failed in [("SPF", spf_fail), ("DKIM", dkim_fail), ("DMARC", dmarc_fail)] if failed]
        report.add_finding(
            category="EMAIL", severity="CRITICAL",
            title=f"Email Authentication Failed: {', '.join(checks)}",
            detail=f"This email failed {', '.join(checks)} validation — strong indicator of email spoofing. "
                   "The sender domain is likely being impersonated.",
            evidence=f"Authentication results in header show: {', '.join(f'{c}=FAIL' for c in checks)}",
            mitre=["T1566.001 – Spearphishing Attachment", "T1036.005 – Match Legitimate Name or Location"]
        )
        report.initial_access = "Email spoofing / phishing (T1566.001)"
        report.what_happened = f"Email spoofing detected. Authentication checks failed: {', '.join(checks)}. " \
                               "The email sender domain was forged to impersonate a trusted sender."
    else:
        report.what_happened = f"Email header analysis complete. {len(parsed_hops)} delivery hops traced. " \
                               f"Originating IP: {originating_ip or 'Unable to determine'}."

    # Suspicious patterns
    suspicious_patterns = [
        ("X-Mailer: The Bat!", "Rare email client sometimes associated with threat actors"),
        ("X-Originating-IP:", "Originating IP exposed in headers"),
    ]
    for pattern, desc in suspicious_patterns:
        if pattern.lower() in header_text.lower():
            report.add_finding("EMAIL", "MEDIUM", f"Suspicious Header: {pattern}",
                               desc, evidence=f"Pattern found: {pattern}")

    report.when_happened = now_str
    report.how_happened = "Email delivered to mailbox — potential phishing or BEC attempt"
    report.next_steps = [
        "✅ Submit originating IP for full threat intelligence lookup",
        "✅ Check sender domain reputation in VT and OTX",
        "✅ Review email gateway rules for similar sender patterns",
        "✅ Interview recipient — determine if links were clicked or attachments opened",
        "✅ Check EDR for any processes spawned from email client",
    ]
    report.containment = [
        "⚠️ Block sender IP at email gateway if confirmed malicious",
        "⚠️ Quarantine similar emails from same sender domain",
        "⚠️ Alert users about phishing attempt",
    ]

    report.finalize()
    return report


# ─── Report Formatter (Telegram HTML) ─────────────────────────────────────────

def format_dfir_report_html(report: DFIRReport, max_findings: int = 8) -> list[str]:
    """
    Format DFIRReport as a list of Telegram HTML messages (split for Telegram's 4096-char limit).
    Returns a list of message chunks.
    """
    import html as _h

    sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
    verdict_emoji = {
        "CONFIRMED THREAT": "🔴", "MALICIOUS": "🟠",
        "SUSPICIOUS": "🟡", "BENIGN": "🟢", "UNKNOWN": "⚪"
    }.get(report.verdict, "⚪")

    pages = []

    # ── PAGE 1: Header + Verdict + What Happened ──────────────────────────────
    p1 = (
        f"🔬 <b>DFIR INVESTIGATION REPORT</b>\n"
        f"<code>{sep}</code>\n"
        f"📁 <b>Case ID:</b>  <code>DFIR-{report.case_id}</code>\n"
        f"📄 <b>Evidence:</b> <code>{_h.escape(report.evidence_name)}</code>\n"
        f"🗂 <b>Type:</b>     <code>{report.evidence_type}</code>\n"
        f"🕒 <b>Analysed:</b> <code>{report.started_at[:19]} UTC</code>\n"
        f"<code>{sep}</code>\n\n"
        f"{verdict_emoji} <b>VERDICT: {report.verdict}</b>\n"
        f"📊 <b>Risk Score:</b> <code>{report.risk_score}/100</code>\n\n"
        f"<b>🔎 WHAT HAPPENED</b>\n"
        f"<code>{sep}</code>\n"
        f"{_h.escape(report.what_happened)}\n\n"
        f"<b>📅 WHEN</b>\n{_h.escape(report.when_happened)}\n\n"
        f"<b>🚪 INITIAL ACCESS</b>\n"
        f"{_h.escape(report.initial_access or 'Under investigation')}\n\n"
        f"<b>🎯 DELIVERY METHOD</b>\n"
        f"{_h.escape(report.how_happened or 'Under investigation')}\n"
    )
    pages.append(p1)

    # ── PAGE 2: Findings ──────────────────────────────────────────────────────
    if report.findings:
        p2 = f"<b>⚠️ FORENSIC FINDINGS ({len(report.findings)} total)</b>\n<code>{sep}</code>\n\n"
        for i, f in enumerate(report.findings[:max_findings], 1):
            p2 += (
                f"{f.severity_emoji} <b>[{f.severity}] {_h.escape(f.title)}</b>\n"
                f"  {_h.escape(f.detail[:200])}\n"
            )
            if f.mitre:
                p2 += f"  🎯 <i>MITRE: {_h.escape(', '.join(f.mitre[:2]))}</i>\n"
            p2 += "\n"
        if len(report.findings) > max_findings:
            p2 += f"<i>… and {len(report.findings) - max_findings} more findings</i>\n"
        pages.append(p2)

    # ── PAGE 3: Evidence + Timeline + MITRE ──────────────────────────────────
    p3 = f"<b>🗂 EVIDENCE SUMMARY</b>\n<code>{sep}</code>\n"
    for e in report.evidence_summary[:8]:
        p3 += f"  • <code>{_h.escape(str(e))}</code>\n"

    if report.attack_timeline:
        p3 += f"\n<b>📅 ATTACK TIMELINE</b>\n<code>{sep}</code>\n"
        for entry in report.attack_timeline[:6]:
            t = _h.escape(str(entry.get("time", "?"))[:24])
            ev = _h.escape(str(entry.get("event", ""))[:100])
            p3 += f"  <code>[{t}]</code> {ev}\n"

    if report.mitre_techniques:
        p3 += f"\n<b>🎯 MITRE ATT&CK TECHNIQUES</b>\n<code>{sep}</code>\n"
        for t in report.mitre_techniques[:10]:
            p3 += f"  • <code>{_h.escape(t)}</code>\n"

    pages.append(p3)

    # ── PAGE 4: Extracted IOCs ────────────────────────────────────────────────
    iocs = report.extracted_iocs
    total_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))
    if total_iocs > 0:
        p4 = f"<b>📡 EXTRACTED IOCs ({total_iocs} total)</b>\n<code>{sep}</code>\n\n"
        if iocs.get("ips"):
            p4 += f"<b>🌐 IPs ({len(iocs['ips'])}):</b>\n"
            for ip in iocs["ips"][:8]:
                p4 += f"  <code>{_h.escape(ip)}</code>\n"
        if iocs.get("domains"):
            p4 += f"\n<b>🔗 Domains ({len(iocs['domains'])}):</b>\n"
            for d in iocs["domains"][:8]:
                p4 += f"  <code>{_h.escape(d)}</code>\n"
        if iocs.get("urls"):
            p4 += f"\n<b>🌍 URLs ({len(iocs['urls'])}):</b>\n"
            for u in iocs["urls"][:5]:
                p4 += f"  <code>{_h.escape(u[:80])}</code>\n"
        if iocs.get("hashes"):
            p4 += f"\n<b>🔒 Hashes ({len(iocs['hashes'])}):</b>\n"
            for h in iocs["hashes"][:5]:
                p4 += f"  <code>{_h.escape(h[:48])}…</code>\n"
        pages.append(p4)

    # ── PAGE 5: Attacker Actions + Affected Systems ───────────────────────────
    p5 = ""
    if report.attacker_actions:
        p5 += f"<b>👤 ATTACKER ACTIONS</b>\n<code>{sep}</code>\n"
        for a in report.attacker_actions[:6]:
            p5 += f"  • {_h.escape(a)}\n"
        p5 += "\n"

    if report.affected_systems:
        p5 += f"<b>🖥 AFFECTED SYSTEMS</b>\n<code>{sep}</code>\n"
        for s in report.affected_systems[:5]:
            p5 += f"  • {_h.escape(s)}\n"
        p5 += "\n"

    if report.next_steps:
        p5 += f"<b>🔭 NEXT INVESTIGATION STEPS</b>\n<code>{sep}</code>\n"
        for s in report.next_steps[:7]:
            p5 += f"  {_h.escape(s)}\n"

    if p5:
        pages.append(p5)

    # ── PAGE 6: Containment ───────────────────────────────────────────────────
    if report.containment:
        p6 = f"<b>🛡 CONTAINMENT RECOMMENDATIONS</b>\n<code>{sep}</code>\n"
        for c in report.containment:
            p6 += f"  {_h.escape(c)}\n"
        p6 += (
            f"\n<code>{sep}</code>\n"
            f"<i>🔬 DFIR-{report.case_id} | Investigator: {_h.escape(report.investigator)}</i>"
        )
        pages.append(p6)

    return pages


# ═══════════════════════════════════════════════════════════════════════════════
# NEW FORENSIC ENGINES — AUTONOMOUS DFIR v2.0
# ═══════════════════════════════════════════════════════════════════════════════

# ─── Entropy Calculator ────────────────────────────────────────────────────────

def _calc_entropy(data: bytes, sample: int = 65536) -> float:
    """Compute Shannon entropy (0-8 scale) for the first `sample` bytes."""
    chunk = data[:sample]
    if not chunk:
        return 0.0
    freq = [0] * 256
    for b in chunk:
        freq[b] += 1
    total = len(chunk)
    return -sum((f / total) * math.log2(f / total) for f in freq if f > 0)


# ─── Timeline Sorter ───────────────────────────────────────────────────────────

def _sort_timeline(report: DFIRReport):
    """Sort attack_timeline placing T+ entries first, then by date string."""
    
# ─── Actionable Evidence and Correlation Engine ─────────────────────────────────

def has_forensic_evidence(report: DFIRReport) -> bool:
    """Check if the report contains any actionable forensic evidence besides metadata."""
    ev = report.extracted_evidence
    keys_to_check = [
        "ips", "domains", "urls", "emails", "hashes",
        "processes", "network_flows", "credentials", "persistence",
        "fs_artifacts", "registry_keys", "api_calls", "vba_macros",
        "obfuscation", "others"
    ]
    for k in keys_to_check:
        if ev.get(k):
            return True
    return False


def correlate_evidence(report: DFIRReport):
    """
    Correlates extracted evidence (IPs, domains, processes) into a pivot dictionary.
    Populates report.correlation_graph: dict[str, list[str]].
    """
    corr = {}
    ev = report.extracted_evidence

    ips = ev.get("ips", [])
    domains = ev.get("domains", [])
    urls = ev.get("urls", [])
    processes = ev.get("processes", [])
    credentials = ev.get("credentials", [])
    registry_keys = ev.get("registry_keys", [])

    # 1. Correlate URLs/Domains/IPs
    import urllib.parse
    for url in urls:
        try:
            parsed = urllib.parse.urlparse(url)
            host = parsed.netloc.split(":")[0] if parsed.netloc else ""
            if host:
                if host in domains or host in ips:
                    if host not in corr:
                        corr[host] = []
                    if url not in corr[host]:
                        corr[host].append(url)
        except Exception:
            pass

    # 2. Correlate processes and network connections
    for proc in processes:
        if proc not in corr:
            corr[proc] = []
        for ip in ips:
            if ip not in corr[proc]:
                corr[proc].append(ip)
        for dom in domains:
            if dom not in corr[proc]:
                corr[proc].append(dom)

    # 3. Correlate credentials with source IPs
    for cred in credentials:
        found_ips = re.findall(r'\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\b', cred)
        for ip in found_ips:
            if ip not in corr:
                corr[ip] = []
            if cred not in corr[ip]:
                corr[ip].append(cred)

    # 4. Correlate registry keys with persistence
    for reg in registry_keys:
        if reg not in corr:
            corr[reg] = []
        for pers in ev.get("persistence", []):
            if pers not in corr[reg]:
                corr[reg].append(pers)

    report.correlation_graph = corr


def extract_evidence_dfir(report: DFIRReport, file_bytes: bytes, filename: str, file_type: str, metadata: dict, anomalies: list, sha256: str):
    """Orchestrates evidence extraction for standard files."""
    ev = None
    if file_type == "pdf":
        ev = _extract_pdf_evidence(metadata, file_bytes, sha256)
    elif file_type in ("png", "jpg", "jpeg", "gif", "webp", "bmp", "ico"):
        ev = _extract_image_evidence(metadata, anomalies, sha256)
    elif file_type == "zip":
        ev = _extract_zip_evidence(metadata, sha256)
    elif file_type == "apk":
        ev = _extract_apk_evidence(metadata, sha256)
    elif file_type in ("pe", "elf"):
        ev = _extract_pe_evidence(file_bytes, filename, sha256)
    elif file_type in ("pcap", "pcapng"):
        extracted, analytics = _extract_pcap_dpkt_evidence(file_bytes, filename)
        if not extracted["ips"] and not extracted["urls"]:
            extracted, analytics = _extract_pcap_heuristic(file_bytes, filename)
        report.extracted_evidence.update(extracted)
        report.network_analytics.update(analytics)
        _merge_iocs(report, extracted)
        return
    elif file_type in ("ole", "docx", "xlsx", "pptx", "ooxml"):
        ev = _extract_office_evidence(file_bytes, filename)
    elif file_type == "memory":
        ev = _extract_memory_evidence(file_bytes, filename)
    elif file_type == "disk":
        ev = _extract_disk_evidence(file_bytes, filename)
    elif file_type in ("script", "php", "xml", "html", "text"):
        ev = _extract_script_evidence(file_bytes, filename)
    else:
        ev = _extract_generic_evidence(file_bytes, filename, sha256)

    if ev:
        report.extracted_evidence.update(ev)
        _merge_iocs(report, ev)


def analyze_evidence_dfir(report: DFIRReport):
    """Unified evidence analyzer routing findings generation."""
    ftype = report.detected_type
    if ftype == "pdf":
        _analyze_pdf_evidence(report)
    elif ftype in ("png", "jpg", "jpeg", "gif", "webp", "bmp", "ico"):
        _analyze_image_evidence(report)
    elif ftype == "zip":
        _analyze_zip_evidence(report)
    elif ftype == "apk":
        _analyze_apk_evidence(report)
    elif ftype in ("pe", "elf"):
        _analyze_pe_evidence(report)
    elif ftype in ("pcap", "pcapng"):
        _analyze_pcap_extracted_evidence(report)
    elif ftype in ("ole", "docx", "xlsx", "pptx", "ooxml"):
        _analyze_office_evidence(report)
    elif ftype == "memory":
        _analyze_memory_evidence(report)
    elif ftype == "disk":
        _analyze_disk_evidence(report)
    elif ftype in ("script", "php", "xml", "html", "text"):
        _analyze_script_evidence(report)
    else:
        _analyze_generic_evidence(report)


# ─── Forensic Extraction & Analysis Implementations ───────────────────────────

def _extract_pdf_evidence(metadata: dict, file_bytes: bytes, sha256: str) -> dict:
    pages = metadata.get("pages", 0)
    has_js = metadata.get("has_js", False)
    has_openaction = metadata.get("has_openaction", False)
    urls = metadata.get("urls", [])
    meta = metadata.get("metadata", {})
    creator = meta.get("Creator", "") or meta.get("Producer", "")
    
    ev = {
        "ips": [], "domains": [], "urls": [], "emails": [], "hashes": [],
        "processes": [], "network_flows": [], "credentials": [], "persistence": [],
        "fs_artifacts": [], "registry_keys": [], "api_calls": [], "metadata": [],
        "vba_macros": [], "obfuscation": [], "others": []
    }
    
    ev["metadata"].append(f"PDF: {pages} pages, JS={has_js}, OpenAction={has_openaction}")
    if creator:
        ev["metadata"].append(f"PDF Creator: {creator}")
        if any(x in creator.lower() for x in ["msfvenom", "metasploit", "exploit", "payload"]):
            ev["others"].append(f"PDF Creator Exploit Signature: {creator}")
            
    if has_js:
        ev["obfuscation"].append("Embedded JavaScript in PDF")
    if has_openaction:
        ev["persistence"].append("PDF Auto-Execution Action (/OpenAction)")
    if urls:
        ev["urls"].extend(urls)
        
    return ev


def _analyze_pdf_evidence(report: DFIRReport):
    ev = report.extracted_evidence
    
    has_js = any("Embedded JavaScript in PDF" in x for x in ev.get("obfuscation", []))
    if has_js:
        report.add_finding(
            category="FILE", severity="CRITICAL",
            title="PDF Contains Embedded JavaScript",
            detail="JavaScript embedded in PDF can be used to execute malicious code when the file is opened. "
                   "This is a strong indicator of a malicious document designed to exploit PDF readers.",
            evidence="Stream contains /JS or /JavaScript directive.",
            mitre=["T1059.007 – JavaScript", "T1204.002 – Malicious File"]
        )
        
    has_open = any("PDF Auto-Execution Action (/OpenAction)" in x for x in ev.get("persistence", []))
    if has_open:
        report.add_finding(
            category="FILE", severity="HIGH",
            title="PDF Auto-Execution Action Detected (/OpenAction)",
            detail="The PDF contains an /OpenAction or /AA directive that triggers code execution automatically "
                   "when the document is opened — a common phishing and exploit delivery technique.",
            evidence="Stream contains /OpenAction or /AA directive.",
            mitre=["T1204 – User Execution", "T1059.007 – JavaScript"]
        )
        
    for o in ev.get("others", []):
        if "PDF Creator Exploit Signature: " in o:
            creator = o.replace("PDF Creator Exploit Signature: ", "")
            report.add_finding("FILE", "CRITICAL", "PDF Created by Exploit Framework",
                               f"Document creator metadata indicates exploit framework: {creator}",
                               mitre=["T1059 – Command and Scripting Interpreter"])
            break
            
    urls = ev.get("urls", [])
    if urls:
        suspicious_urls = [u for u in urls if any(x in u.lower() for x in
                           ["bit.ly", "tinyurl", "pastebin", "ngrok", "webhook", "raw.github"])]
        severity = "HIGH" if suspicious_urls else "MEDIUM"
        report.add_finding(
            category="FILE", severity=severity,
            title=f"PDF Embeds {len(urls)} Hyperlinks",
            detail=f"Found {len(urls)} embedded URLs. Suspicious redirectors detected: {suspicious_urls or 'None'}. "
                   "Hyperlinks may point to phishing pages or malware C2 infrastructure.",
            evidence="Sample: " + " | ".join(urls[:3]),
            mitre=["T1566.001 – Spearphishing Attachment"] if suspicious_urls else []
        )
        
    pages_meta = [m for m in ev.get("metadata", []) if "PDF: " in m]
    if pages_meta:
        report.evidence_summary.append(pages_meta[0])
    creator_meta = [m for m in ev.get("metadata", []) if "PDF Creator: " in m]
    if creator_meta:
        report.evidence_summary.append(creator_meta[0])


def _extract_image_evidence(exif: dict, anomalies: list, sha256: str) -> dict:
    ev = {
        "ips": [], "domains": [], "urls": [], "emails": [], "hashes": [],
        "processes": [], "network_flows": [], "credentials": [], "persistence": [],
        "fs_artifacts": [], "registry_keys": [], "api_calls": [], "metadata": [],
        "vba_macros": [], "obfuscation": [], "others": []
    }
    if not exif:
        return ev
        
    software = exif.get("Software", "")
    gps = exif.get("GPSInfo", "")
    date_taken = exif.get("DateTime", "")

    if date_taken:
        ev["metadata"].append(f"Image Captured: {date_taken}")
    if gps:
        ev["metadata"].append("GPSInfo present")
    if software:
        ev["metadata"].append(f"Image Software: {software}")
        
    if anomalies:
        ev["obfuscation"].extend(anomalies)
        
    return ev


def _analyze_image_evidence(report: DFIRReport):
    ev = report.extracted_evidence
    
    date_meta = [m for m in ev.get("metadata", []) if "Image Captured: " in m]
    if date_meta:
        date_taken = date_meta[0].replace("Image Captured: ", "")
        report.evidence_summary.append(f"Image Captured: {date_taken}")
        report.attack_timeline.append({"time": date_taken, "event": "Image captured (EXIF timestamp)"})
        
    gps_meta = any("GPSInfo present" in m for m in ev.get("metadata", []))
    if gps_meta:
        report.add_finding(
            category="FILE", severity="HIGH",
            title="GPS Location Data Exposed in Image Metadata",
            detail="Image EXIF metadata contains GPS coordinates. This can expose the physical location "
                   "where the image was taken — a serious privacy and operational security risk.",
            evidence="EXIF: GPSInfo field present",
            mitre=["T1592.002 – Gather Victim Host Information"]
        )
        
    software_meta = [m for m in ev.get("metadata", []) if "Image Software: " in m]
    if software_meta:
        software = software_meta[0].replace("Image Software: ", "")
        if any(sw in software.lower() for sw in ["gimp", "photoshop", "exiftool", "paint.net", "canva"]):
            report.add_finding(
                category="FILE", severity="MEDIUM",
                title=f"Image Digitally Manipulated — {software}",
                detail=f"EXIF metadata shows the image was processed by {software}. "
                       "This may indicate tampering with document or identity evidence.",
                evidence=f"EXIF Software: {software}",
                mitre=["T1036 – Masquerading"]
            )


def _extract_zip_evidence(zip_info: dict, sha256: str) -> dict:
    files = zip_info.get("files", [])
    hidden = zip_info.get("hidden_files", [])
    encrypted = zip_info.get("encrypted", False)
    total_size = zip_info.get("total_size", 0)
    
    ev = {
        "ips": [], "domains": [], "urls": [], "emails": [], "hashes": [],
        "processes": [], "network_flows": [], "credentials": [], "persistence": [],
        "fs_artifacts": [], "registry_keys": [], "api_calls": [], "metadata": [],
        "vba_macros": [], "obfuscation": [], "others": []
    }
    
    ev["metadata"].append(f"ZIP Archive: {len(files)} files, {total_size/1024:.1f} KB uncompressed, encrypted={encrypted}")
    if encrypted:
        ev["obfuscation"].append("Password-Protected ZIP Archive")
    if hidden:
        ev["others"].extend([f"Hidden file: {f}" for f in hidden])
        
    dangerous_exts = (".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".lnk", ".scr", ".com", ".hta")
    dangerous_files = [f["name"] for f in files if any(f["name"].lower().endswith(ext) for ext in dangerous_exts)]
    if dangerous_files:
        ev["fs_artifacts"].extend(dangerous_files)
        
    return ev


def _analyze_zip_evidence(report: DFIRReport):
    ev = report.extracted_evidence
    
    zip_meta = [m for m in ev.get("metadata", []) if "ZIP Archive: " in m]
    if zip_meta:
        report.evidence_summary.append(zip_meta[0])
        
    encrypted = any("Password-Protected ZIP Archive" in x for x in ev.get("obfuscation", []))
    if encrypted:
        report.add_finding(
            category="FILE", severity="MEDIUM",
            title="Password-Protected ZIP Archive",
            detail="Encrypted archives are commonly used to evade antivirus scanning and deliver payloads "
                   "that bypass email gateways. The password is typically sent separately.",
            evidence="ZIP encryption flag set.",
            mitre=["T1027 – Obfuscated Files or Information", "T1566.001 – Spearphishing Attachment"]
        )
        
    hidden = [o.replace("Hidden file: ", "") for o in ev.get("others", []) if o.startswith("Hidden file: ")]
    if hidden:
        report.add_finding(
            category="FILE", severity="HIGH",
            title=f"Hidden Files in Archive: {len(hidden)} Found",
            detail=f"Files prefixed with '.' (hidden on Unix/Linux) found inside archive: {hidden[:5]}. "
                   "Hidden files in archives are a red flag for concealed payloads or configuration files.",
            evidence=f"Hidden files: {', '.join(hidden[:3])}",
            mitre=["T1036 – Masquerading", "T1027 – Obfuscated Files"]
        )
        
    dangerous_files = ev.get("fs_artifacts", [])
    dangerous_exts = (".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".lnk", ".scr", ".com", ".hta")
    dangerous_files_filtered = [f for f in dangerous_files if any(f.lower().endswith(ext) for ext in dangerous_exts)]
    if dangerous_files_filtered:
        report.add_finding(
            category="FILE", severity="CRITICAL",
            title=f"Executable Payloads in Archive: {len(dangerous_files_filtered)} Files",
            detail=f"Archive contains potentially malicious executables: {dangerous_files_filtered[:5]}. "
                   "ZIP archives containing executables are a primary malware delivery vector.",
            evidence=f"Files: {', '.join(dangerous_files_filtered[:3])}",
            mitre=["T1204.002 – Malicious File", "T1566.001 – Spearphishing Attachment"]
        )


def _extract_apk_evidence(apk_info: dict, sha256: str) -> dict:
    package = apk_info.get("package_name", "Unknown")
    permissions = apk_info.get("permissions", [])
    file_count = apk_info.get("files_count", 0)
    
    ev = {
        "ips": [], "domains": [], "urls": [], "emails": [], "hashes": [],
        "processes": [], "network_flows": [], "credentials": [], "persistence": [],
        "fs_artifacts": [], "registry_keys": [], "api_calls": [], "metadata": [],
        "vba_macros": [], "obfuscation": [], "others": []
    }
    
    ev["metadata"].append(f"APK: {package}, {file_count} files, {len(permissions)} permissions")
    
    dangerous_perms = ["SEND_SMS", "RECEIVE_SMS", "RECORD_AUDIO", "CAMERA", "READ_CONTACTS", "WRITE_SETTINGS", "READ_CALL_LOG", "PROCESS_OUTGOING_CALLS"]
    for perm in permissions:
        pname = perm.split(".")[-1].upper()
        if pname in dangerous_perms:
            ev["api_calls"].append(f"APK Permission: {perm}")
            
    return ev


def _analyze_apk_evidence(report: DFIRReport):
    ev = report.extracted_evidence
    
    apk_meta = [m for m in ev.get("metadata", []) if "APK: " in m]
    if apk_meta:
        report.evidence_summary.append(apk_meta[0])
        parts = apk_meta[0].split(", ")
        package = parts[0].replace("APK: ", "")
    else:
        package = "Unknown"
        
    dangerous_perms = {
        "SEND_SMS":        ("T1437 – Alternative Network Mediums", "SMS fraud / exfiltration"),
        "RECEIVE_SMS":     ("T1430 – Location Tracking", "SMS interception"),
        "RECORD_AUDIO":    ("T1429 – Capture Audio", "Covert audio surveillance"),
        "CAMERA":          ("T1512 – Video Capture", "Covert video surveillance"),
        "READ_CONTACTS":   ("T1636.003 – Contact List", "Contact data theft"),
        "WRITE_SETTINGS":  ("T1631 – Boot or Logon Initialization", "System manipulation"),
        "READ_CALL_LOG":   ("T1636.002 – Call Log", "Call log theft"),
        "PROCESS_OUTGOING_CALLS": ("T1430 – Location Tracking", "Call interception"),
    }
    
    found_dangerous = []
    for perm_call in ev.get("api_calls", []):
        if perm_call.startswith("APK Permission: "):
            perm = perm_call.replace("APK Permission: ", "")
            pname = perm.split(".")[-1].upper()
            if pname in dangerous_perms:
                mitre_id, reason = dangerous_perms[pname]
                found_dangerous.append(pname)
                report.add_finding(
                    category="FILE", severity="HIGH",
                    title=f"Dangerous APK Permission: {pname}",
                    detail=f"APK requests sensitive permission: {pname}. Risk: {reason}.",
                    evidence=f"Permission: {perm}",
                    mitre=[mitre_id]
                )
                
    if len(found_dangerous) >= 3:
        report.add_finding(
            category="FILE", severity="CRITICAL",
            title=f"APK Requests {len(found_dangerous)} Dangerous Permissions — Spyware Pattern",
            detail=f"The combination of {', '.join(found_dangerous[:5])} permissions is consistent with "
                   "stalkerware, spyware, or banking trojans.",
            evidence=f"Package: {package}",
            mitre=["T1421 – Port Knocking", "T1430 – Location Tracking", "T1429 – Capture Audio"]
        )

_SUSPICIOUS_APIS = [
    "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "SetWindowsHookEx", "GetAsyncKeyState", "NtUnmapViewOfSection", "RtlDecompressBuffer",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "CreateProcess", "ShellExecute", "WinExec", "URLDownloadToFile",
    "InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest",
    "WSAStartup", "connect", "send", "recv", "gethostbyname",
    "RegSetValueEx", "RegCreateKey", "CryptEncrypt", "CryptDecrypt",
    "FindFirstFile", "MoveFile", "DeleteFile", "GetTempPath",
    "OpenProcess", "TerminateProcess", "SuspendThread",
    "LoadLibrary", "GetProcAddress",
]

_PE_SUSPICIOUS_PATTERNS = [
    (r'https?://[^\s\x00]{8,120}',   "Embedded URL (possible C2)",     "T1071.001 – Web Protocols"),
    (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', "Hardcoded IP address",            "T1071 – Application Layer Protocol"),
    (r'powershell|cmd\.exe|wscript', "Shell execution string",           "T1059 – Command & Scripting Interpreter"),
    (r'mimikatz|sekurlsa|lsass',      "Credential dumping tool string",  "T1003.001 – LSASS Memory"),
    (r'cobalt|beacon|stager',         "Cobalt Strike artifact string",   "T1071.001 – C2 Beaconing"),
    (r'vssadmin|shadowcopy|bcdedit',  "Shadow copy deletion string",     "T1490 – Inhibit System Recovery"),
    (r'wget|curl|certutil',           "Download tool string",            "T1105 – Ingress Tool Transfer"),
    (r'runas|whoami|net\s+user',      "Privilege/recon string",          "T1033 – System Owner Discovery"),
    (r'HKCU|HKLM|CurrentVersion\\Run', "Registry persistence key",      "T1547.001 – Registry Run Keys"),
    (r'schtasks|at\.exe',            "Scheduled task creation",         "T1053.005 – Scheduled Task"),
]


def _extract_pe_evidence(data: bytes, filename: str, sha256: str) -> dict:
    is_elf = data[:4] == b"\x7fELF"
    ftype_label = "ELF" if is_elf else "PE"
    size_kb = len(data) / 1024
    
    ev = {
        "ips": [], "domains": [], "urls": [], "emails": [], "hashes": [],
        "processes": [], "network_flows": [], "credentials": [], "persistence": [],
        "fs_artifacts": [], "registry_keys": [], "api_calls": [], "metadata": [],
        "vba_macros": [], "obfuscation": [], "others": []
    }
    
    ev["metadata"].append(f"{ftype_label} Binary: {filename} ({size_kb:.1f} KB)")
    
    if not is_elf:
        try:
            if len(data) >= 64:
                e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
                if e_lfanew + 24 <= len(data):
                    pe_sig = data[e_lfanew:e_lfanew+4]
                    if pe_sig == b"PE\x00\x00":
                        machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
                        num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
                        timestamp = struct.unpack_from("<I", data, e_lfanew + 8)[0]
                        characteristics = struct.unpack_from("<H", data, e_lfanew + 22)[0]
                        
                        machine_name = {0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM"}.get(machine, hex(machine))
                        compile_time = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if timestamp else "Unknown"
                        
                        ev["metadata"].append(f"PE Compiled: {compile_time}")
                        ev["metadata"].append(f"PE Machine: {machine_name}")
                        ev["metadata"].append(f"PE Section Count: {num_sections}")
                        if characteristics & 0x2000:
                            ev["metadata"].append("PE Type: DLL")
                        
                        if timestamp > datetime.now(timezone.utc).timestamp():
                            ev["others"].append("PE compile time is in the future")
        except Exception:
            pass

    printable = re.findall(rb"[\x20-\x7e]{6,}", data)
    strings = [s.decode("ascii", errors="ignore") for s in printable[:500]]
    strings_text = "\n".join(strings)
    
    found_apis = [api for api in _SUSPICIOUS_APIS if api.lower() in strings_text.lower()]
    ev["api_calls"].extend(found_apis)
    
    for pattern, label, mitre_id in _PE_SUSPICIOUS_PATTERNS:
        matches = re.findall(pattern, strings_text, re.IGNORECASE)
        if matches:
            for match in matches[:5]:
                match_str = str(match)
                if label == "Embedded URL (possible C2)":
                    if match_str not in ev["urls"]:
                        ev["urls"].append(match_str)
                        try:
                            import urllib.parse
                            dom = urllib.parse.urlparse(match_str).netloc
                            if dom and dom not in ev["domains"]:
                                ev["domains"].append(dom)
                        except Exception:
                            pass
                elif label == "Hardcoded IP address":
                    if not any(match_str.startswith(p) for p in _PRIVATE_PREFIXES):
                        if match_str not in ev["ips"]:
                            ev["ips"].append(match_str)
                elif label == "Registry persistence key":
                    if match_str not in ev["registry_keys"]:
                        ev["registry_keys"].append(match_str)
                    if match_str not in ev["persistence"]:
                        ev["persistence"].append(match_str)
                elif label == "Credential dumping tool string":
                    if match_str not in ev["credentials"]:
                        ev["credentials"].append(match_str)
                elif label == "Scheduled task creation" or label == "Shadow copy deletion string":
                    if match_str not in ev["persistence"]:
                        ev["persistence"].append(match_str)
                elif label == "Shell execution string" or label == "Download tool string" or label == "Privilege/recon string":
                    if match_str not in ev["processes"]:
                        ev["processes"].append(match_str)
                        
    return ev


def _analyze_pe_evidence(report: DFIRReport):
    ev = report.extracted_evidence
    is_elf = report.detected_type == "elf"
    ftype_label = "ELF" if is_elf else "PE"
    
    comp_time = None
    for meta in ev.get("metadata", []):
        if "PE Compiled: " in meta:
            comp_time = meta.replace("PE Compiled: ", "")
            report.attack_timeline.append({"time": comp_time, "event": f"PE binary compiled ({[m for m in ev['metadata'] if 'PE Machine: ' in m][0] if any('PE Machine: ' in m for m in ev['metadata']) else 'unknown'})"})
            
    if "PE compile time is in the future" in ev.get("others", []):
        report.add_finding(
            category="FILE", severity="HIGH",
            title="PE: Future Compile Timestamp — Timestamp Manipulation Detected",
            detail=f"The PE compile timestamp ({comp_time or 'future'}) is set in the future. "
                   "This is a common defense evasion technique to confuse analysts and bypass timeline correlation.",
            mitre=["T1036 – Masquerading", "T1027 – Obfuscated Files"]
        )
        
    apis = ev.get("api_calls", [])
    if apis:
        severity = "CRITICAL" if len(apis) >= 5 else "HIGH" if len(apis) >= 2 else "MEDIUM"
        report.add_finding(
            category="FILE", severity=severity,
            title=f"{ftype_label}: {len(apis)} Suspicious API Calls Detected",
            detail=f"Binary references dangerous Windows APIs commonly used in malware: "
                   f"{', '.join(apis[:8])}. This strongly indicates malicious behavior "
                   f"(injection, persistence, C2 communication, or credential harvesting).",
            evidence=f"APIs: {', '.join(apis[:5])}",
            mitre=["T1055 – Process Injection", "T1071 – Application Layer Protocol"]
        )
        
    if ev.get("registry_keys"):
        report.add_finding(
            category="FILE", severity="HIGH",
            title=f"{ftype_label}: Persistence Registry Keys Referenced",
            detail=f"Binary references registry keys used for persistence: {', '.join(ev['registry_keys'][:5])}.",
            evidence=f"Registry: {', '.join(ev['registry_keys'][:3])}",
            mitre=["T1547.001 – Registry Run Keys"]
        )
        
    if ev.get("credentials"):
        report.add_finding(
            category="FILE", severity="CRITICAL",
            title=f"{ftype_label}: Credential Harvesting Code Patterns",
            detail="Binary contains references to credential harvesting tools or functions.",
            evidence=f"Keywords: {', '.join(ev['credentials'][:5])}",
            mitre=["T1003.001 – LSASS Memory"]
        )
        
    for pers in ev.get("persistence", []):
        if "schtasks" in pers or "at.exe" in pers:
            report.add_finding(
                category="FILE", severity="HIGH",
                title=f"{ftype_label}: Scheduled Task API Referenced",
                detail="Binary references scheduled task tools for persistent execution.",
                mitre=["T1053.005 – Scheduled Task"]
            )
            break
            
    if not report.what_happened:
        report.what_happened = (
            f"A {ftype_label} binary '{report.evidence_name}' was submitted for static analysis. "
            f"{len(apis)} suspicious API calls identified. "
            f"{len(ev.get('urls', [])) + len(ev.get('ips', []))} IOCs extracted from strings."
        )
        
    report.attack_timeline.append({
        "time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "event": f"{ftype_label} binary analysed: {len(apis)} suspicious APIs"
    })


def _extract_office_evidence(data: bytes, filename: str) -> dict:
    ev = {
        "ips": [], "domains": [], "urls": [], "emails": [], "hashes": [],
        "processes": [], "network_flows": [], "credentials": [], "persistence": [],
        "fs_artifacts": [], "registry_keys": [], "api_calls": [], "metadata": [],
        "vba_macros": [], "obfuscation": [], "others": []
    }
    size_kb = len(data) / 1024
    ev["metadata"].append(f"Office Document: {filename} ({size_kb:.1f} KB)")
    
    macro_found = False
    vba_code = ""
    embedded_urls = []
    
    try:
        import olefile
        if olefile.isOleFile(data):
            ole = olefile.OleFileIO(io.BytesIO(data))
            streams = ole.listdir()
            ev["metadata"].append(f"OLE2 document: {len(streams)} streams")
            
            for entry in streams:
                stream_name = "/".join(str(e) for e in entry).lower()
                if "vba" in stream_name or "macro" in stream_name:
                    try:
                        stream_data = ole.openstream(entry).read()
                        text = stream_data.decode("latin-1", errors="ignore")
                        vba_code += text + "\n"
                        macro_found = True
                    except Exception:
                        pass
            ole.close()
    except Exception:
        pass
        
    if not vba_code:
        try:
            import zipfile
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for name in zf.namelist():
                    if "vbaproject" in name.lower() or "macro" in name.lower():
                        vba_code += zf.read(name).decode("latin-1", errors="ignore")
                        macro_found = True
                for name in zf.namelist():
                    if name.endswith(".xml") or name.endswith(".rels"):
                        try:
                            xml_text = zf.read(name).decode("utf-8", errors="ignore")
                            urls = re.findall(r'https?://[^\s\'"<>{}\r\n\t\f\v\'\"]{8,200}', xml_text)
                            embedded_urls.extend(urls)
                        except Exception:
                            pass
        except Exception:
            pass
            
    raw_text = data.decode("latin-1", errors="ignore")
    iocs = extract_iocs_from_text(raw_text + " " + vba_code)
    embedded_urls.extend(iocs.get("urls", []))
    
    if macro_found or any(kw in raw_text.lower() for kw in ["autoopen", "document_open", "workbook_open", "sub ", "function "]):
        ev["vba_macros"].append("Embedded VBA Macros present")
        
    vba_scan_text = vba_code + raw_text
    for keyword, label, mitre_id in _VBA_DANGEROUS:
        if keyword.lower() in vba_scan_text.lower():
            if keyword in ("Shell", "AutoOpen", "Document_Open", "Workbook_Open"):
                ev["persistence"].append(f"Dangerous macro trigger: {keyword}")
            if keyword in ("URLDownloadToFile", "CreateObject", "WScript.Shell"):
                ev["api_calls"].append(f"VBA API: {keyword}")
            if keyword in ("Chr(", "Base64"):
                ev["obfuscation"].append(f"VBA obfuscation technique: {keyword}")
                
    if embedded_urls:
        ev["urls"].extend(list(set(embedded_urls)))
        import urllib.parse
        for u in embedded_urls:
            try:
                dom = urllib.parse.urlparse(u).netloc
                if dom and dom not in ev["domains"]:
                    ev["domains"].append(dom)
            except Exception:
                pass
                
    return ev


def _analyze_office_evidence(report: DFIRReport):
    ev = report.extracted_evidence
    
    for m in ev.get("metadata", []):
        report.evidence_summary.append(m)
        
    macro_found = len(ev.get("vba_macros", [])) > 0
    if macro_found:
        report.add_finding(
            category="DOCUMENT", severity="HIGH",
            title="VBA Macro Detected in Office Document",
            detail="The document contains embedded VBA macros. Malicious macros are one of the most common "
                   "initial access vectors for malware campaigns, particularly in phishing attacks.",
            evidence="Embedded VBA Macros present",
            mitre=["T1137.001 – Office Template Macros", "T1566.001 – Spearphishing Attachment"]
        )
        report.initial_access = "Malicious Office macro — T1566.001 Spearphishing Attachment"
        
        for p in ev.get("persistence", []):
            if "Dangerous macro trigger: " in p:
                keyword = p.replace("Dangerous macro trigger: ", "")
                label = [lbl for kw, lbl, m in _VBA_DANGEROUS if kw == keyword][0]
                mitre_id = [m for kw, lbl, m in _VBA_DANGEROUS if kw == keyword][0]
                report.add_finding(
                    category="DOCUMENT", severity="CRITICAL",
                    title=f"Macro: {label} ({keyword})",
                    detail=f"Macro code references '{keyword}': {label}. "
                           "This pattern is associated with malware document builders and exploit kits.",
                    evidence=f"Keyword found: {keyword}",
                    mitre=[mitre_id]
                )
        for api in ev.get("api_calls", []):
            if "VBA API: " in api:
                keyword = api.replace("VBA API: ", "")
                label = [lbl for kw, lbl, m in _VBA_DANGEROUS if kw == keyword][0]
                mitre_id = [m for kw, lbl, m in _VBA_DANGEROUS if kw == keyword][0]
                report.add_finding(
                    category="DOCUMENT", severity="CRITICAL" if keyword == "URLDownloadToFile" else "HIGH",
                    title=f"Macro: {label} ({keyword})",
                    detail=f"Macro code references '{keyword}': {label}. "
                           "This pattern is associated with malware document builders and exploit kits.",
                    evidence=f"Keyword found: {keyword}",
                    mitre=[mitre_id]
                )
        for obf in ev.get("obfuscation", []):
            if "VBA obfuscation technique: " in obf:
                keyword = obf.replace("VBA obfuscation technique: ", "")
                label = [lbl for kw, lbl, m in _VBA_DANGEROUS if kw == keyword][0]
                mitre_id = [m for kw, lbl, m in _VBA_DANGEROUS if kw == keyword][0]
                report.add_finding(
                    category="DOCUMENT", severity="HIGH",
                    title=f"Macro: {label} ({keyword})",
                    detail=f"Macro code references '{keyword}': {label}.",
                    evidence=f"Keyword found: {keyword}",
                    mitre=[mitre_id]
                )
    else:
        report.add_finding(
            category="DOCUMENT", severity="INFO",
            title="No VBA Macros Detected",
            detail="Document does not appear to contain executable VBA macros. "
                   "Embedded URLs and objects were still extracted for IOC analysis.",
        )
        
    embedded_urls = ev.get("urls", [])
    if embedded_urls:
        suspicious = [u for u in embedded_urls if any(x in u.lower() for x in
                      ["bit.ly", "pastebin", "ngrok", "raw.github", "tinyurl", "webhook"])]
        report.add_finding(
            category="DOCUMENT",
            severity="HIGH" if suspicious else "MEDIUM",
            title=f"Embedded URLs: {len(set(embedded_urls))} Found",
            detail=f"Document contains {len(set(embedded_urls))} embedded URL(s). "
                   f"Suspicious redirectors/C2 URLs: {suspicious[:3] or 'None'}.",
            evidence="Sample: " + ", ".join(list(set(embedded_urls))[:3]),
            mitre=["T1566.001 – Spearphishing Attachment"]
        )
        
    if not report.what_happened:
        report.what_happened = (
            f"Office document '{report.evidence_name}' analysed. "
            f"Macros present: {'YES — MALICIOUS INDICATORS FOUND' if macro_found else 'No'}. "
            f"Embedded URLs: {len(set(embedded_urls))}."
        )


def _extract_memory_evidence(data: bytes, filename: str) -> dict:
    ev = {
        "ips": [], "domains": [], "urls": [], "emails": [], "hashes": [],
        "processes": [], "network_flows": [], "credentials": [], "persistence": [],
        "fs_artifacts": [], "registry_keys": [], "api_calls": [], "metadata": [],
        "vba_macros": [], "obfuscation": [], "others": []
    }
    size_mb = len(data) / (1024 * 1024)
    ev["metadata"].append(f"Memory Artifact: {filename} ({size_mb:.1f} MB)")
    
    raw_text = data.decode("latin-1", errors="ignore")
    
    found_procs = []
    for pattern in _MEMORY_PROCESS_PATTERNS:
        matches = re.findall(pattern, raw_text, re.IGNORECASE)
        found_procs.extend(set(matches))
    if found_procs:
        ev["processes"].extend(list(set(found_procs)))
        
    for keyword, label, mitre_id in _MEMORY_MALWARE_STRINGS:
        if keyword.lower() in raw_text.lower():
            if keyword in ("mimikatz", "sekurlsa", "lsass", "pwdump", "procdump"):
                ev["credentials"].append(f"Memory signature: {label} ({keyword})")
            elif keyword in ("schtasks /create", "reg add"):
                ev["persistence"].append(f"Memory signature: {label} ({keyword})")
            else:
                ev["others"].append(f"Memory signature: {label} ({keyword})")
                
    iocs = extract_iocs_from_text(raw_text)
    ev["ips"].extend(iocs.get("ips", []))
    ev["domains"].extend(iocs.get("domains", []))
    ev["urls"].extend(iocs.get("urls", []))
    
    return ev


def _analyze_memory_evidence(report: DFIRReport):
    ev = report.extracted_evidence

    # Build a safe lookup dict: keyword -> (label, mitre_id)
    # Handles keywords from both dfir_engine._MEMORY_MALWARE_STRINGS
    # and dfir_streaming._MALWARE_STRINGS (which may differ)
    _kw_map = {kw: (lbl, mid) for kw, lbl, mid in _MEMORY_MALWARE_STRINGS}

    for m in ev.get("metadata", []):
        report.evidence_summary.append(m)

    procs = ev.get("processes", [])
    if procs:
        report.evidence_summary.append(f"Process names found in memory: {', '.join(procs[:10])}")
        report.add_finding(
            category="MEMORY", severity="INFO",
            title=f"Process Artifacts in Memory: {len(procs)} Processes Identified",
            detail=f"Memory strings reveal process names: {', '.join(procs[:8])}. "
                   "Suspicious processes (e.g., cmd.exe, rundll32, mshta) in memory may indicate "
                   "malicious execution or process injection.",
            evidence=f"Processes: {', '.join(procs[:5])}",
            mitre=["T1057 - Process Discovery"]
        )

    def _emit_finding(sig_str: str, default_severity: str):
        """Parse a 'Memory signature: Label (keyword)' string and emit a finding safely."""
        # Extract the parenthetical keyword, e.g. 'mimikatz' from '... (mimikatz)'
        m = re.findall(r'\(([^)]+)\)', sig_str)
        if not m:
            return
        keyword = m[-1]  # use last parenthetical group
        lbl, mid = _kw_map.get(keyword, (sig_str, "T1059 - Command and Scripting"))
        report.add_finding(
            category="MEMORY", severity=default_severity,
            title=f"Memory: {lbl} String Detected",
            detail=f"Memory artifact contains the string '{keyword}' which is associated with: {lbl}. "
                   "This is a high-confidence indicator of active malware execution in the memory of a compromised host.",
            evidence=f"String found: {keyword}",
            mitre=[mid]
        )

    for cred in ev.get("credentials", []):
        if "Memory signature: " in cred:
            _emit_finding(cred, "CRITICAL")

    for pers in ev.get("persistence", []):
        if "Memory signature: " in pers:
            _emit_finding(pers, "HIGH")

    for oth in ev.get("others", []):
        if "Memory signature: " in oth:
            _emit_finding(oth, "CRITICAL")

    total_iocs = len(ev.get("ips", [])) + len(ev.get("domains", [])) + len(ev.get("urls", []))
    if total_iocs:
        report.add_finding(
            category="MEMORY", severity="HIGH",
            title=f"Network IOCs in Memory: {total_iocs} Indicators",
            detail=f"Extracted {len(ev.get('ips', []))} IPs, {len(ev.get('domains', []))} domains, "
                   f"{len(ev.get('urls', []))} URLs from memory strings.",
            evidence=f"IPs: {', '.join(ev.get('ips', [])[:3])}",
            mitre=["T1071 - Application Layer Protocol", "T1041 - Exfiltration"]
        )

    if not report.what_happened:
        report.what_happened = (
            f"Memory artifact '{report.evidence_name}' ({len(procs)} processes, {total_iocs} IOCs) analyzed."
        )

    report.attack_timeline.append({
        "time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "event": f"Memory analysed: {len(procs)} processes, {total_iocs} IOCs"
    })


def _extract_disk_evidence(data: bytes, filename: str) -> dict:
    ev = {
        "ips": [], "domains": [], "urls": [], "emails": [], "hashes": [],
        "processes": [], "network_flows": [], "credentials": [], "persistence": [],
        "fs_artifacts": [], "registry_keys": [], "api_calls": [], "metadata": [],
        "vba_macros": [], "obfuscation": [], "others": []
    }
    size_mb = len(data) / (1024 * 1024)
    ev["metadata"].append(f"Disk Image: {filename} ({size_mb:.1f} MB — partial, Telegram 20MB limit)")
    
    if len(data) >= 512 and data[510:512] == b"\x55\xaa":
        ev["metadata"].append("MBR Partition Table (0x55AA)")
        
    raw_text = data.decode("latin-1", errors="ignore")
    
    win_artifacts = {
        "$MFT":         "NTFS Master File Table detected",
        "$LogFile":     "NTFS LogFile journal detected",
        "prefetch":     "Windows Prefetch artifacts detected",
        "SYSTEM32":     "Windows System32 path reference",
        "pagefile.sys": "Windows pagefile reference",
        "hiberfil.sys": "Hibernation file reference",
    }
    for artifact, desc in win_artifacts.items():
        if artifact.lower() in raw_text.lower():
            ev["fs_artifacts"].append(artifact)
            
    iocs = extract_iocs_from_text(raw_text)
    ev["ips"].extend(iocs.get("ips", []))
    ev["domains"].extend(iocs.get("domains", []))
    ev["urls"].extend(iocs.get("urls", []))
    
    return ev


def _analyze_disk_evidence(report: DFIRReport):
    ev = report.extracted_evidence
    
    for m in ev.get("metadata", []):
        report.evidence_summary.append(m)
        
    report.add_finding(
        category="DISK", severity="HIGH",
        title="Disk Image Submitted — Heuristic Forensic Carving Scan",
        detail="Disk image received. Performing heuristic string extraction on available data.",
    )
    
    if any("MBR Partition Table" in m for m in ev.get("metadata", [])):
        report.add_finding(
            category="DISK", severity="INFO",
            title="MBR Partition Signature Detected (0x55AA)",
            detail="Master Boot Record (MBR) signature found. The disk uses MBR partitioning.",
            mitre=["T1542.003 – Bootkit"]
        )
        
    win_artifacts = {
        "$MFT":         "NTFS Master File Table detected",
        "$LogFile":     "NTFS LogFile journal detected",
        "prefetch":     "Windows Prefetch artifacts detected",
        "SYSTEM32":     "Windows System32 path reference",
        "pagefile.sys": "Windows pagefile reference",
        "hiberfil.sys": "Hibernation file reference",
    }
    for art in ev.get("fs_artifacts", []):
        if art in win_artifacts:
            report.add_finding(
                category="DISK", severity="INFO",
                title=f"Disk Artifact: {win_artifacts[art]}",
                detail=f"Windows filesystem artifact '{art}' found in disk image.",
                evidence=f"Artifact: {art}"
            )
            
    if not report.what_happened:
        report.what_happened = (
            f"Disk image '{report.evidence_name}' partially analysed."
        )


def _extract_script_evidence(data: bytes, filename: str) -> dict:
    ev = {
        "ips": [], "domains": [], "urls": [], "emails": [], "hashes": [],
        "processes": [], "network_flows": [], "credentials": [], "persistence": [],
        "fs_artifacts": [], "registry_keys": [], "api_calls": [], "metadata": [],
        "vba_macros": [], "obfuscation": [], "others": []
    }
    text = data.decode("utf-8", errors="ignore") or data.decode("latin-1", errors="ignore")
    ev["metadata"].append(f"Script: {filename} ({len(text)} chars)")
    
    for pattern, label, mitre_id in _SCRIPT_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            if label == "Base64 obfuscation":
                ev["obfuscation"].append(f"Script obfuscation: {label}")
            elif label == "PowerShell IEX execution" or label == "Web download" or label == "WebClient object":
                ev["api_calls"].append(f"Script execution API: {label}")
            elif label == "Linux persistence/creds":
                ev["persistence"].append(f"Script persistence hint: {label}")
            elif label == "Credential dumping":
                ev["credentials"].append(f"Script credential tools: {label}")
            elif label == "Reverse shell" or label == "Background execution" or label == "Shell execution":
                ev["processes"].append(f"Script shell spawn: {label}")
                
    iocs = extract_iocs_from_text(text)
    ev["ips"].extend(iocs.get("ips", []))
    ev["domains"].extend(iocs.get("domains", []))
    ev["urls"].extend(iocs.get("urls", []))
    
    return ev


def _analyze_script_evidence(report: DFIRReport):
    ev = report.extracted_evidence
    
    for m in ev.get("metadata", []):
        report.evidence_summary.append(m)
        
    findings_count = 0
    
    for obf in ev.get("obfuscation", []):
        if "Script obfuscation: " in obf:
            label = obf.replace("Script obfuscation: ", "")
            mitre_id = [m for pat, lbl, m in _SCRIPT_PATTERNS if lbl == label][0]
            findings_count += 1
            report.add_finding(
                category="SCRIPT", severity="HIGH",
                title=f"Script: {label}",
                detail=f"Script contains pattern associated with '{label}'.",
                mitre=[mitre_id]
            )
    for api in ev.get("api_calls", []):
        if "Script execution API: " in api:
            label = api.replace("Script execution API: ", "")
            mitre_id = [m for pat, lbl, m in _SCRIPT_PATTERNS if lbl == label][0]
            findings_count += 1
            report.add_finding(
                category="SCRIPT", severity="HIGH",
                title=f"Script: {label}",
                detail=f"Script contains pattern associated with '{label}'.",
                mitre=[mitre_id]
            )
    for pers in ev.get("persistence", []):
        if "Script persistence hint: " in pers:
            label = pers.replace("Script persistence hint: ", "")
            mitre_id = [m for pat, lbl, m in _SCRIPT_PATTERNS if lbl == label][0]
            findings_count += 1
            report.add_finding(
                category="SCRIPT", severity="HIGH",
                title=f"Script: {label}",
                detail=f"Script contains pattern associated with '{label}'.",
                mitre=[mitre_id]
            )
    for cred in ev.get("credentials", []):
        if "Script credential tools: " in cred:
            label = cred.replace("Script credential tools: ", "")
            mitre_id = [m for pat, lbl, m in _SCRIPT_PATTERNS if lbl == label][0]
            findings_count += 1
            report.add_finding(
                category="SCRIPT", severity="HIGH",
                title=f"Script: {label}",
                detail=f"Script contains pattern associated with '{label}'.",
                mitre=[mitre_id]
            )
    for proc in ev.get("processes", []):
        if "Script shell spawn: " in proc:
            label = proc.replace("Script shell spawn: ", "")
            mitre_id = [m for pat, lbl, m in _SCRIPT_PATTERNS if lbl == label][0]
            findings_count += 1
            report.add_finding(
                category="SCRIPT", severity="HIGH",
                title=f"Script: {label}",
                detail=f"Script contains pattern associated with '{label}'.",
                mitre=[mitre_id]
            )
            
    total_iocs = len(ev.get("ips", [])) + len(ev.get("domains", [])) + len(ev.get("urls", []))
    if not report.what_happened:
        report.what_happened = (
            f"Script '{report.evidence_name}' analysed. {findings_count} patterns detected. "
            f"{total_iocs} IOCs extracted."
        )
    report.initial_access = "Malicious script delivery — T1059 Command & Scripting Interpreter"


def _extract_generic_evidence(data: bytes, filename: str, sha256: str) -> dict:
    ev = {
        "ips": [], "domains": [], "urls": [], "emails": [], "hashes": [],
        "processes": [], "network_flows": [], "credentials": [], "persistence": [],
        "fs_artifacts": [], "registry_keys": [], "api_calls": [], "metadata": [],
        "vba_macros": [], "obfuscation": [], "others": []
    }
    size_kb = len(data) / 1024
    entropy = _calc_entropy(data)
    ev["metadata"].append(f"Unknown file: {filename} ({size_kb:.1f} KB, entropy={entropy:.2f})")
    
    if entropy > 7.0:
        ev["obfuscation"].append("High Shannon Entropy (likely packed/obfuscated)")
        
    iocs = extract_iocs_from_text(data.decode("latin-1", errors="ignore"))
    ev["ips"].extend(iocs.get("ips", []))
    ev["domains"].extend(iocs.get("domains", []))
    ev["urls"].extend(iocs.get("urls", []))
    
    return ev


def _analyze_generic_evidence(report: DFIRReport):
    ev = report.extracted_evidence
    
    entropy = 0.0
    for m in ev.get("metadata", []):
        report.evidence_summary.append(m)
        if "entropy=" in m:
            entropy = float(m.split("entropy=")[-1].replace(")", ""))
            
    total = len(ev.get("ips", [])) + len(ev.get("domains", [])) + len(ev.get("urls", []))
    has_obf = any("High Shannon Entropy" in x for x in ev.get("obfuscation", []))
    
    report.add_finding(
        category="FILE",
        severity="MEDIUM" if total > 0 or has_obf else "INFO",
        title="Unknown Binary: Heuristic Scan Complete",
        detail=f"Unrecognized file type processed via generic forensic scanner. "
               f"Entropy: {entropy:.2f}/8.0 ({'HIGH — likely packed/encrypted' if has_obf else 'Normal'}). "
               f"{total} IOCs extracted.",
        evidence=f"File entropy: {entropy:.2f}",
        mitre=["T1027 – Obfuscated Files"] if has_obf else []
    )
    
    if not report.what_happened:
        report.what_happened = (
            f"Unknown file '{report.evidence_name}' submitted. Entropy: {entropy:.2f}/8.0. "
            f"{total} IOCs extracted."
        )

# ─── Legacy Wrappers for Backwards Compatibility ──────────────────────────────

def _analyze_pdf_dfir(report: DFIRReport, metadata: dict, file_bytes: bytes, sha256: str):
    ev = _extract_pdf_evidence(metadata, file_bytes, sha256)
    report.extracted_evidence.update(ev)
    _merge_iocs(report, ev)
    _analyze_pdf_evidence(report)

def _analyze_image_dfir(report: DFIRReport, exif: dict, anomalies: list, sha256: str):
    ev = _extract_image_evidence(exif, anomalies, sha256)
    report.extracted_evidence.update(ev)
    _merge_iocs(report, ev)
    _analyze_image_evidence(report)

def _analyze_zip_dfir(report: DFIRReport, zip_info: dict, sha256: str):
    ev = _extract_zip_evidence(zip_info, sha256)
    report.extracted_evidence.update(ev)
    _merge_iocs(report, ev)
    _analyze_zip_evidence(report)

def _analyze_apk_dfir(report: DFIRReport, apk_info: dict, sha256: str):
    ev = _extract_apk_evidence(apk_info, sha256)
    report.extracted_evidence.update(ev)
    _merge_iocs(report, ev)
    _analyze_apk_evidence(report)

def analyze_pcap_dfir(report: DFIRReport, data: bytes, filename: str):
    """Heuristic PCAP analysis using pure-Python struct parsing."""
    report.evidence_type = "PCAP"
    report.initial_access = "Network traffic capture — analysing for C2, exfiltration, lateral movement"

    # Try dpkt first
    try:
        import dpkt
        _analyze_pcap_dpkt(report, data, filename)
        return
    except ImportError:
        pass
    except Exception as e:
        logger.warning(f"[PCAP/dpkt] Error: {e}")

    _analyze_pcap_heuristic(report, data, filename)


def _extract_pcap_dpkt_evidence(data: bytes, filename: str) -> tuple[dict, dict]:
    import dpkt
    import io
    import base64
    import urllib.parse
    from collections import defaultdict

    extracted = {
        "ips": [],
        "domains": [],
        "urls": [],
        "emails": [],
        "hashes": [],
        "network_flows": [],
        "credentials": [],
        "metadata": [],
        "others": []
    }
    
    analytics = {
        "top_talkers": [],
        "port_breakdown": {},
        "beaconing_sessions": [],
        "credentials": []
    }

    try:
        pcap_file = dpkt.pcap.Reader(io.BytesIO(data))
    except Exception:
        try:
            pcap_file = dpkt.pcapng.Reader(io.BytesIO(data))
        except Exception as e:
            logger.warning(f"dpkt PCAP open failed: {e}")
            return extracted, analytics

    dns_queries:  list[str] = []
    http_hosts:   list[str] = []
    src_ips:      set[str]  = set()
    dst_ips:      set[str]  = set()
    packet_times: dict[str, list[float]] = defaultdict(list)
    pkt_count     = 0
    
    ip_stats = {} # ip -> {connections, bytes_sent, bytes_received, ports: set, syn_count, login_attempts, suspicious_ua_count}
    port_counts = defaultdict(int)
    detected_logins = []
    web_attacks = []
    suspicious_ua = []

    def init_ip(ip_addr):
        if ip_addr not in ip_stats:
            ip_stats[ip_addr] = {
                "connections": 0,
                "bytes_sent": 0,
                "bytes_received": 0,
                "ports": set(),
                "syn_count": 0,
                "login_attempts": 0,
                "suspicious_ua_count": 0
            }

    _PRIV = ("127.", "0.", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")

    try:
        for ts, pkt in pcap_file:
            pkt_count += 1
            if pkt_count > 15000:
                break
            try:
                eth = dpkt.ethernet.Ethernet(pkt)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data

                src = ".".join(str(b) for b in ip.src)
                dst = ".".join(str(b) for b in ip.dst)

                init_ip(src)
                init_ip(dst)

                pkt_len = len(pkt)
                ip_stats[src]["bytes_sent"] += pkt_len
                ip_stats[src]["connections"] += 1
                ip_stats[dst]["bytes_received"] += pkt_len
                ip_stats[dst]["connections"] += 1

                if not any(src.startswith(p) for p in _PRIV):
                    src_ips.add(src)
                if not any(dst.startswith(p) for p in _PRIV):
                    dst_ips.add(dst)

                packet_times[dst].append(ts)

                # TCP packet analysis
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    dport = tcp.dport
                    sport = tcp.sport
                    
                    port_counts[dport] += 1
                    ip_stats[src]["ports"].add(dport)
                    ip_stats[dst]["ports"].add(sport)
                    
                    extracted["network_flows"].append(f"TCP {src}:{sport} -> {dst}:{dport}")

                    # Plaintext FTP login credentials
                    if dport == 21 and tcp.data:
                        payload = tcp.data.decode("utf-8", errors="ignore")
                        if payload.upper().startswith("USER "):
                            detected_logins.append({
                                "proto": "FTP",
                                "src": src, "dst": dst,
                                "user": payload[5:].strip(),
                                "pass": None
                            })
                            ip_stats[src]["login_attempts"] += 1
                        elif payload.upper().startswith("PASS "):
                            for l in reversed(detected_logins):
                                if l["proto"] == "FTP" and l["src"] == src and l["dst"] == dst and l["pass"] is None:
                                    l["pass"] = payload[5:].strip()
                                    break

                    # Plaintext HTTP connection parsing
                    if dport in (80, 8080, 8000) and tcp.data:
                        try:
                            http = dpkt.http.Request(tcp.data)
                            host = http.headers.get("host", "")
                            if host:
                                http_hosts.append(host)
                            
                            uri = http.uri
                            extracted["urls"].append(f"{http.method} {host}{uri}")

                            # Basic Authentication extractor
                            auth = http.headers.get("authorization", "")
                            if auth.lower().startswith("basic "):
                                try:
                                    decoded = base64.b64decode(auth[6:].strip()).decode("utf-8", errors="ignore")
                                    if ":" in decoded:
                                        u, p = decoded.split(":", 1)
                                        detected_logins.append({
                                            "proto": "HTTP-Basic",
                                            "src": src, "dst": dst,
                                            "user": u, "pass": p
                                        })
                                        ip_stats[src]["login_attempts"] += 1
                                except Exception:
                                    pass

                            # POST credentials parser
                            body = http.body
                            if body and isinstance(body, bytes):
                                body_str = body.decode("utf-8", errors="ignore").lower()
                                params = urllib.parse.parse_qs(body_str)
                                user_keys = ["user", "username", "login", "email", "usr"]
                                pass_keys = ["pass", "password", "passwd", "pwd"]
                                found_user = None
                                found_pass = None
                                for k, v in params.items():
                                    if any(uk in k for uk in user_keys) and v:
                                        found_user = v[0]
                                    if any(pk in k for pk in pass_keys) and v:
                                        found_pass = v[0]
                                if found_user or found_pass:
                                    detected_logins.append({
                                        "proto": f"HTTP-POST ({http.method})",
                                        "src": src, "dst": dst,
                                        "user": found_user or "[Not Found]",
                                        "pass": found_pass or "[Not Found]"
                                    })
                                    ip_stats[src]["login_attempts"] += 1

                            # Heuristics for common web vulnerabilities (SQLi, Directory Traversal, XSS)
                            uri_dec = urllib.parse.unquote(http.uri)
                            attacks = []
                            uri_lower = uri_dec.lower()
                            if "union select" in uri_lower or "select " in uri_lower and "from" in uri_lower:
                                attacks.append("SQL Injection")
                            if "../" in uri_dec or "..\\" in uri_dec or "etc/passwd" in uri_lower or "boot.ini" in uri_lower:
                                attacks.append("Path Traversal / LFI")
                            if "<script>" in uri_lower or "javascript:" in uri_lower or "onerror" in uri_lower:
                                attacks.append("Cross-Site Scripting (XSS)")

                            if attacks:
                                web_attacks.append({
                                    "type": ", ".join(attacks),
                                    "src": src, "dst": dst,
                                    "uri": uri_dec[:80]
                                })

                            # Scanner / Malicious User-Agent Check
                            ua = http.headers.get("user-agent", "")
                            if ua:
                                ua_lower = ua.lower()
                                suspicious_ua_sigs = ["sqlmap", "nmap", "nikto", "hydra", "dirbuster", "gobuster", "w3af", "metasploit", "nessus", "netsparker", "acunetix"]
                                if any(sig in ua_lower for sig in suspicious_ua_sigs):
                                    suspicious_ua.append(f"{src} using {ua[:50]}")
                                    ip_stats[src]["suspicious_ua_count"] += 1
                        except Exception:
                            pass

                    # Connection brute-force tracker
                    if tcp.flags & dpkt.tcp.TH_SYN and not tcp.flags & dpkt.tcp.TH_ACK:
                        ip_stats[src]["syn_count"] += 1

                # UDP / DNS query parsing
                if isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    dport = udp.dport
                    sport = udp.sport
                    port_counts[dport] += 1
                    ip_stats[src]["ports"].add(dport)
                    ip_stats[dst]["ports"].add(sport)
                    
                    extracted["network_flows"].append(f"UDP {src}:{sport} -> {dst}:{dport}")

                    if dport == 53 and udp.data:
                        try:
                            dns = dpkt.dns.DNS(udp.data)
                            for q in dns.qd:
                                name = q.name.decode(errors="ignore") if isinstance(q.name, bytes) else q.name
                                if name:
                                    dns_queries.append(name)
                        except Exception:
                            pass
            except Exception:
                continue
    except Exception as e:
        logger.warning(f"PCAP packet iteration error: {e}")

    # Process Top Talkers
    top_talkers = []
    for ip_addr, stats in ip_stats.items():
        conns = stats["connections"]
        sent = stats["bytes_sent"]
        recv = stats["bytes_received"]
        total_bytes = sent + recv
        
        # Scoring
        score = 0
        port_count = len(stats["ports"])
        if port_count > 10:
            score += 30
        if stats["syn_count"] > 50:
            score += 30
        if stats["login_attempts"] > 5:
            score += 40
        if sent > 10 * 1024 * 1024:
            score += 20
        elif sent > 1 * 1024 * 1024:
            score += 10
        if stats["suspicious_ua_count"] > 0:
            score += 35

        score = min(100, score)

        # Classification
        if score >= 50:
            classification = "Malicious"
            role = "Suspicious"
        elif score >= 20:
            classification = "Suspicious"
            role = "Suspicious"
        else:
            classification = "Normal"
            if recv > sent * 2:
                role = "Server"
            else:
                role = "Client"

        top_talkers.append({
            "ip": ip_addr,
            "connections": conns,
            "bytes_sent": sent,
            "bytes_received": recv,
            "bytes_transferred": total_bytes,
            "role": role,
            "score": score,
            "classification": classification
        })

    top_talkers.sort(key=lambda x: x["bytes_transferred"], reverse=True)
    analytics["top_talkers"] = top_talkers
    analytics["port_breakdown"] = dict(port_counts)

    # Process Beaconing
    beaconing_sessions = []
    for target_ip, times in packet_times.items():
        if len(times) >= 20:
            beacon_score = _detect_beaconing(times)
            if beacon_score > 0.7:
                times_sorted = sorted(times)
                diffs = [times_sorted[i] - times_sorted[i-1] for i in range(1, len(times_sorted))]
                diffs_sorted = sorted(diffs)
                median_interval = diffs_sorted[len(diffs_sorted)//2] if diffs_sorted else 0
                beaconing_sessions.append({
                    "target_ip": target_ip,
                    "interval": f"{median_interval:.2f}s",
                    "confidence": f"{beacon_score:.0%}"
                })
    analytics["beaconing_sessions"] = beaconing_sessions

    # Process Credentials
    credentials_list = []
    for l in detected_logins:
        usr = l["user"]
        pwd = l["pass"] or "[No Pass]"
        cred_str = f"User: {usr}, Pass: {pwd}"
        credentials_list.append({
            "ip": l["src"],
            "proto": l["proto"],
            "type": "plaintext",
            "credential": cred_str
        })
        extracted["credentials"].append(f"{l['proto']} login from {l['src']} to {l['dst']}: {cred_str}")
    analytics["credentials"] = credentials_list

    # Populate general extracted fields
    extracted["ips"] = list(src_ips | dst_ips)
    extracted["domains"] = list(set(dns_queries + http_hosts))
    
    extracted["metadata"].append(f"PCAP: {pkt_count} packets processed")
    extracted["metadata"].append(f"Source IPs: {len(src_ips)}, Destination IPs: {len(dst_ips)}")
    
    # Store web attacks / UAs in others
    for wa in web_attacks:
        extracted["others"].append(f"Web application attack: {wa['type']} from {wa['src']} to {wa['dst']}")
    for ua in suspicious_ua:
        extracted["others"].append(f"Suspicious tool User-Agent: {ua}")
    for b in beaconing_sessions:
        extracted["others"].append(f"C2 Beaconing session detected to target {b['target_ip']} at interval {b['interval']}")

    return extracted, analytics


def _extract_pcap_heuristic(data: bytes, filename: str) -> tuple[dict, dict]:
    raw_text = data.decode("latin-1", errors="ignore")
    iocs = extract_iocs_from_text(raw_text)
    
    extracted = {
        "ips": iocs["ips"],
        "domains": iocs["domains"],
        "urls": iocs["urls"],
        "emails": iocs["emails"],
        "hashes": iocs["hashes"],
        "network_flows": [],
        "credentials": [],
        "metadata": [f"Heuristic PCAP file: {filename}"],
        "others": ["Heuristic parsing mode only"]
    }
    
    top_talkers = []
    for ip in iocs["ips"][:10]:
        top_talkers.append({
            "ip": ip,
            "connections": 1,
            "bytes_sent": 0,
            "bytes_received": 0,
            "bytes_transferred": 0,
            "role": "Suspicious",
            "score": 25,
            "classification": "Suspicious"
        })
        
    analytics = {
        "top_talkers": top_talkers,
        "port_breakdown": {},
        "beaconing_sessions": [],
        "credentials": []
    }
    return extracted, analytics


def _analyze_pcap_extracted_evidence(report: DFIRReport):
    ev = report.extracted_evidence
    net = report.network_analytics
    
    # Report credentials found
    creds = net.get("credentials", [])
    if creds:
        summary_logins = [f"{c['proto']} ({c['ip']}): {c['credential']}" for c in creds[:5]]
        report.add_finding(
            category="NETWORK", severity="CRITICAL",
            title=f"Plaintext Login Credentials Extracted: {len(creds)} Credentials Found",
            detail="The network capture contains plaintext protocol logins. Plaintext authentication "
                   "allows attackers to perform eavesdropping and credentials harvesting. Extracted:\n" +
                   "\n".join(summary_logins),
            evidence=f"Logins: {', '.join(c['ip'] for c in creds[:5])}",
            mitre=["T1040 – Network Sniffing", "T1552.001 – Credentials in Files"]
        )

    # Report web attacks
    web_attacks = [o for o in ev.get("others", []) if "Web application attack:" in o]
    if web_attacks:
        report.add_finding(
            category="NETWORK", severity="HIGH",
            title=f"Web Application Attack Payloads Detected: {len(web_attacks)} Attempts",
            detail="Detected typical exploit attempts on web applications (e.g. SQLi, LFI, XSS). Details:\n" +
                   "\n".join(web_attacks[:5]),
            evidence=f"Attacks: {len(web_attacks)} attempts detected",
            mitre=["T1190 – Exploit Public-Facing Application"]
        )

    # Report suspicious User-Agents
    susp_ua = [o for o in ev.get("others", []) if "Suspicious tool User-Agent:" in o]
    if susp_ua:
        report.add_finding(
            category="NETWORK", severity="HIGH",
            title=f"Suspicious Exploit Tool User-Agents: {len(susp_ua)} unique",
            detail="Vulnerability scanner or offensive tools (e.g. sqlmap, hydra, nmap) user-agents identified: " +
                   ", ".join(susp_ua[:5]),
            evidence=f"Scanners detected: {len(susp_ua)} hits",
            mitre=["T1595 – Active Scanning"]
        )

    # Report port scanning / connection brute-forcing
    heavy_scanners = []
    talkers = net.get("top_talkers", [])
    for t in talkers:
        if t["score"] >= 20 and t["classification"] in ("Suspicious", "Malicious"):
            heavy_scanners.append(f"{t['ip']} classified as {t['classification']} (Score: {t['score']}/100, Conns: {t['connections']})")
    if heavy_scanners:
        report.add_finding(
            category="NETWORK", severity="HIGH",
            title="Network Connection Brute-Force / Port Scan Detected",
            detail="High connection intensity, SYN packet counts, or port diversity indicate active port scans or brute-force attempts:\n" +
                   "\n".join(heavy_scanners[:5]),
            evidence=f"SYN scans: {len(heavy_scanners)} hosts flagged",
            mitre=["T1110 – Brute Force", "T1046 – Network Service Discovery"]
        )

    # Report DNS queries
    dns_queries = [d for d in ev.get("domains", [])]
    if dns_queries:
        suspicious_dns = [d for d in dns_queries if _is_suspicious_domain(d)]
        severity = "HIGH" if suspicious_dns else "MEDIUM"
        report.add_finding(
            category="NETWORK", severity=severity,
            title=f"DNS Queries Detected: {len(dns_queries)} unique domains",
            detail=f"Network capture contains {len(dns_queries)} DNS queries. "
                   f"Suspicious domains: {suspicious_dns[:5] or 'None identified'}.",
            evidence="Sample: " + ", ".join(dns_queries[:5]),
            mitre=["T1071.004 – DNS", "T1568 – Dynamic Resolution"]
        )

    # Report HTTP hosts
    if ev.get("urls"):
        unique_hosts = list(set([u.split(" ")[1].split("/")[0] for u in ev.get("urls") if " " in u]))
        if unique_hosts:
            report.add_finding(
                category="NETWORK", severity="MEDIUM",
                title=f"HTTP Traffic to {len(unique_hosts)} Unique Hosts",
                detail=f"Plain HTTP (unencrypted) connections detected. Hosts: {', '.join(unique_hosts[:5])}. "
                       "Unencrypted C2 channels may transmit commands and stolen data in plaintext.",
                evidence="Hosts: " + ", ".join(unique_hosts[:5]),
                mitre=["T1071.001 – Web Protocols"]
            )

    # Report beaconing
    beacons = net.get("beaconing_sessions", [])
    if beacons:
        for b in beacons:
            report.add_finding(
                category="NETWORK", severity="CRITICAL",
                title=f"C2 Beaconing Pattern Detected (Confidence: {b['confidence']})",
                detail=f"Network traffic shows highly regular packet intervals consistent with C2 beacon activity. "
                       f"Target IP: {b['target_ip']} at interval: {b['interval']}.",
                evidence=f"Beacon target: {b['target_ip']}",
                mitre=["T1071.001 – Web Protocols C2", "T1132 – Data Encoding", "T1041 – Exfiltration Over C2"]
            )
            report.what_happened = (
                f"Network capture reveals active C2 beaconing. "
                f"A compromised host is communicating with {b['target_ip']} in a regular pattern (interval: {b['interval']})."
            )

    # Report external IPs
    external_ips = ev.get("ips", [])
    if external_ips:
        report.add_finding(
            category="NETWORK", severity="MEDIUM",
            title=f"External IP Communication: {len(external_ips)} Addresses",
            detail=f"Traffic captured with {len(external_ips)} external IP addresses.",
            evidence=f"IPs: {', '.join(external_ips[:5])}",
            mitre=["T1041 – Exfiltration Over C2 Channel"]
        )

    if not report.what_happened:
        # Check if logins or scans happened to set a descriptive summary
        if creds:
            report.what_happened = (
                f"Network capture contains plaintext logins. "
                f"Extracted {len(creds)} plaintext credentials (FTP, HTTP Basic, or HTTP POST)."
            )
        else:
            report.what_happened = (
                f"PCAP file contains network capture traffic. "
                f"Detected {len(dns_queries)} DNS queries and communication with "
                f"{len(external_ips)} external IP addresses."
            )


def _analyze_pcap_dpkt(report: DFIRReport, data: bytes, filename: str):
    """Full PCAP analysis using dpkt."""
    extracted, analytics = _extract_pcap_dpkt_evidence(data, filename)
    report.extracted_evidence.update(extracted)
    report.network_analytics.update(analytics)

    report.extracted_iocs["ips"] = list(set(report.extracted_iocs.get("ips", []) + extracted["ips"]))[:20]
    report.extracted_iocs["domains"] = list(set(report.extracted_iocs.get("domains", []) + extracted["domains"]))[:20]
    report.extracted_iocs["urls"] = list(set(report.extracted_iocs.get("urls", []) + extracted["urls"]))[:20]

    _analyze_pcap_extracted_evidence(report)

    report.attack_timeline.append({
        "time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "event": f"PCAP analysed: {len(extracted['network_flows'])} flows, {len(extracted['ips'])} ext IPs, {len(extracted['domains'])} DNS/Hosts"
    })


def _analyze_pcap_heuristic(report: DFIRReport, data: bytes, filename: str):
    """Fallback PCAP analysis using string extraction."""
    extracted, analytics = _extract_pcap_heuristic(data, filename)
    report.extracted_evidence.update(extracted)
    report.network_analytics.update(analytics)

    report.extracted_iocs["ips"] = list(set(report.extracted_iocs.get("ips", []) + extracted["ips"]))[:20]
    report.extracted_iocs["domains"] = list(set(report.extracted_iocs.get("domains", []) + extracted["domains"]))[:20]
    report.extracted_iocs["urls"] = list(set(report.extracted_iocs.get("urls", []) + extracted["urls"]))[:20]

    _analyze_pcap_extracted_evidence(report)



def _is_suspicious_domain(domain: str) -> bool:
    """Heuristic: flag domains that look like DGA or known-bad TLDs."""
    bad_tlds = (".top", ".xyz", ".tk", ".pw", ".cc", ".ml", ".ga", ".cf", ".su", ".bit")
    if any(domain.endswith(t) for t in bad_tlds):
        return True
    # Entropy-based DGA detection: random-looking label
    label = domain.split(".")[0]
    if len(label) >= 12 and _calc_entropy(label.encode()) > 3.5:
        return True
    return False


def _detect_beaconing(times: list[float]) -> float:
    """
    Compute a beaconing regularity score (0-1).
    Higher = more regular intervals (consistent with C2 beacon).
    """
    if len(times) < 10:
        return 0.0
    times = sorted(times)
    intervals = [times[i+1] - times[i] for i in range(len(times)-1) if times[i+1] - times[i] > 0]
    if not intervals:
        return 0.0
    avg = sum(intervals) / len(intervals)
    if avg == 0:
        return 0.0
    variance = sum((x - avg) ** 2 for x in intervals) / len(intervals)
    std_dev = math.sqrt(variance)
    cv = std_dev / avg  # Coefficient of variation (0=perfectly regular)
    return max(0.0, min(1.0, 1 - cv))


# ─── Office Document Analyzer (DOC/DOCX/XLS/XLSX/OLE) ────────────────────────

_VBA_DANGEROUS = [
    ("Shell",            "Shell execution via VBA",    "T1059.005 – Visual Basic"),
    ("AutoOpen",         "Auto-execute macro",         "T1137.001 – Office Template Macros"),
    ("Document_Open",    "Auto-execute on open",       "T1137.001 – Office Template Macros"),
    ("Workbook_Open",    "Auto-execute on open",       "T1137.001 – Office Template Macros"),
    ("CreateObject",     "COM object instantiation",   "T1559 – Inter-Process Communication"),
    ("WScript.Shell",    "WScript shell execution",    "T1059.005 – VBScript"),
    ("PowerShell",       "PowerShell invocation",      "T1059.001 – PowerShell"),
    ("cmd.exe",          "CMD execution",              "T1059.003 – Windows Command Shell"),
    ("URLDownloadToFile","File download from web",     "T1105 – Ingress Tool Transfer"),
    ("Chr(",             "Character obfuscation",      "T1027 – Obfuscated Files"),
    ("Base64",           "Base64 encoding",            "T1027 – Obfuscated Files"),
    ("Environ",          "Environment variable access","T1082 – System Information Discovery"),
]


# ─── Memory Dump Analyzer (Heuristic) ────────────────────────────────────────

_MEMORY_PROCESS_PATTERNS = [
    r'(?:svchost|lsass|csrss|winlogon|explorer|cmd|powershell|rundll32|regsvr32|mshta|wscript|cscript|certutil)\.exe',
]
_MEMORY_MALWARE_STRINGS = [
    ("mimikatz",        "Mimikatz credential harvester",     "T1003.001 – LSASS Memory"),
    ("sekurlsa",        "Sekurlsa module (Mimikatz)",        "T1003.001 – LSASS Memory"),
    ("cobalt strike",   "Cobalt Strike implant",             "T1071.001 – Web Protocols C2"),
    ("beacon.dll",      "Cobalt Strike beacon DLL",          "T1071.001 – C2 Beaconing"),
    ("metasploit",      "Metasploit framework artifact",     "T1071 – Application Layer Protocol"),
    ("meterpreter",     "Meterpreter payload",               "T1059 – Command & Scripting"),
    ("procdump",        "Process dump tool",                 "T1003 – OS Credential Dumping"),
    ("pwdump",          "Password dumping tool",             "T1003 – OS Credential Dumping"),
    ("psexec",          "Lateral movement via PsExec",       "T1021.002 – SMB Admin Shares"),
    ("pass-the-hash",   "Pass-the-Hash attack",              "T1550.002 – Pass the Hash"),
    ("vssadmin delete", "Shadow copy deletion",              "T1490 – Inhibit System Recovery"),
    ("netsh firewall",  "Firewall rule manipulation",        "T1562.004 – Disable Firewall"),
    ("schtasks /create","Scheduled task persistence",        "T1053.005 – Scheduled Task"),
    ("reg add",         "Registry modification",             "T1112 – Modify Registry"),
]


# ─── Disk Image Analyzer (Heuristic) ─────────────────────────────────────────

# ─── Script Analyzer ─────────────────────────────────────────────────────────

_SCRIPT_PATTERNS = [
    (r'base64|frombase64string|convert::frombase64', "Base64 obfuscation",     "T1027 – Obfuscated Files"),
    (r'invoke-expression|iex\s*\(',               "PowerShell IEX execution", "T1059.001 – PowerShell"),
    (r'downloadstring|downloadfile|webclient',     "Web download",             "T1105 – Ingress Tool Transfer"),
    (r'new-object.*webclient',                     "WebClient object",         "T1105 – Ingress Tool Transfer"),
    (r'invoke-mimikatz|mimikatz',                  "Credential dumping",       "T1003.001 – LSASS Memory"),
    (r'set-executionpolicy\s+bypass',              "Execution policy bypass",  "T1059.001 – PowerShell"),
    (r'wscript\.shell|shell\.run',                "Shell execution",          "T1059.005 – Visual Basic"),
    (r'crontab|/etc/passwd|/etc/shadow',           "Linux persistence/creds",  "T1003 – OS Credential Dumping"),
    (r'nc\s+-e|/bin/sh|/bin/bash',                "Reverse shell",            "T1059.004 – Unix Shell"),
    (r'nohup|disown|&\s*$',                        "Background execution",     "T1059.004 – Unix Shell"),
]


# ─── Generic Binary / Unknown Analyzer ────────────────────────────────────────

# ─── IOC Merger ───────────────────────────────────────────────────────────────

def _merge_iocs(report: DFIRReport, new_iocs: dict):
    """Merge newly extracted IOCs into the report's existing IOC dict."""
    for key in ("ips", "domains", "urls", "emails", "hashes", "filenames"):
        existing = report.extracted_iocs.get(key, [])
        incoming = new_iocs.get(key, [])
        merged = list(dict.fromkeys(existing + incoming))  # deduplicate, preserve order
        report.extracted_iocs[key] = merged[:30]


# ─── Attack Chain Reconstruction Engine ──────────────────────────────────────

_KILL_CHAIN_MITRE_MAP = {
    "Initial Access":        ["T1566", "T1190", "T1133", "T1078", "T1204"],
    "Execution":             ["T1059", "T1204", "T1047", "T1053", "T1218"],
    "Persistence":           ["T1547", "T1053", "T1543", "T1037", "T1136"],
    "Privilege Escalation":  ["T1134", "T1055", "T1068", "T1078"],
    "Defense Evasion":       ["T1027", "T1036", "T1055", "T1218", "T1562"],
    "Credential Access":     ["T1003", "T1056", "T1110", "T1555", "T1552"],
    "Discovery":             ["T1033", "T1016", "T1049", "T1082", "T1018"],
    "Lateral Movement":      ["T1021", "T1550", "T1080", "T1210"],
    "Collection":            ["T1074", "T1114", "T1056", "T1213"],
    "Exfiltration":          ["T1041", "T1048", "T1567"],
    "Impact":                ["T1486", "T1490", "T1489", "T1485"],
    "Command & Control":     ["T1071", "T1095", "T1132", "T1573", "T1008"],
}


def reconstruct_attack_chain(report: DFIRReport) -> list[dict]:
    """
    Map findings, MITRE techniques and extracted evidence to kill chain phases.
    Returns ordered list of {phase, techniques, evidence, status, confidence}.
    """
    if not has_forensic_evidence(report):
        return []
        
    chain: list[dict] = []
    found_techniques = set()
    for t in report.mitre_techniques:
        m = re.match(r'(T\d{4})', t)
        if m:
            found_techniques.add(m.group(1))

    ev = report.extracted_evidence
    phase_evidence_map = {
        "Initial Access": ev.get("emails", []) + [u for u in ev.get("urls", []) if "phish" in u.lower() or "bit.ly" in u.lower()],
        "Execution": ev.get("api_calls", []) + ev.get("vba_macros", []),
        "Persistence": ev.get("persistence", []) + ev.get("registry_keys", []),
        "Privilege Escalation": [p for p in ev.get("processes", []) if "runas" in p or "bypass" in p],
        "Defense Evasion": ev.get("obfuscation", []),
        "Credential Access": ev.get("credentials", []),
        "Discovery": [p for p in ev.get("processes", []) if "whoami" in p or "netstat" in p or "ipconfig" in p],
        "Lateral Movement": [p for p in ev.get("processes", []) if "psexec" in p or "wmic" in p],
        "Command & Control": [u for u in ev.get("urls", []) if "beacon" in u.lower() or "c2" in u.lower()],
        "Exfiltration": ev.get("network_flows", [])[:5],
        "Impact": [o for o in ev.get("others", []) if "ransom" in o.lower() or "encrypt" in o.lower()]
    }

    for phase, phase_techniques in _KILL_CHAIN_MITRE_MAP.items():
        matched = [t for t in phase_techniques if t in found_techniques]
        evidence_list = []
        
        for f in report.findings:
            for m in f.mitre:
                tid = re.match(r'(T\d{4})', m)
                if tid and tid.group(1) in phase_techniques:
                    evidence_list.append(f.title)
                    break
                    
        if phase in phase_evidence_map:
            evidence_list.extend(str(item) for item in phase_evidence_map[phase])

        if matched or evidence_list:
            status = "CONFIRMED"
            confidence = min(96, 50 + len(matched) * 15 + len(evidence_list) * 10)
        else:
            status = "INFERRED"
            confidence = 25

        chain.append({
            "phase": phase,
            "techniques": matched or [],
            "evidence": list(dict.fromkeys(evidence_list))[:3],
            "status": status,
            "confidence": confidence,
        })

    return chain

_HYPOTHESIS_PROFILES: list[dict] = [
    {
        "name":          "Ransomware Attack",
        "attack_type":   "Ransomware",
        "family_hints":  ["WannaCry", "LockBit", "Ryuk", "REvil", "BlackCat"],
        "indicators":    ["vssadmin", "bcdedit", ".locky", "encrypt", "ransom", "T1486", "T1490"],
        "base_confidence": 70,
    },
    {
        "name":          "Credential Harvesting / InfoStealer",
        "attack_type":   "InfoStealer",
        "family_hints":  ["Mimikatz", "RedLine", "Raccoon", "AZORult", "Vidar"],
        "indicators":    ["mimikatz", "sekurlsa", "lsass", "T1003", "T1555", "T1056"],
        "base_confidence": 65,
    },
    {
        "name":          "Remote Access Trojan (RAT) / C2 Beaconing",
        "attack_type":   "RAT / C2",
        "family_hints":  ["AsyncRAT", "Cobalt Strike", "njRAT", "QuasarRAT", "NanoCore"],
        "indicators":    ["beacon", "cobalt", "T1071", "T1095", "VirtualAllocEx", "CreateRemoteThread"],
        "base_confidence": 65,
    },
    {
        "name":          "Phishing / Spearphishing Campaign",
        "attack_type":   "Phishing",
        "family_hints":  ["Generic Phishing", "BEC", "Spearphishing"],
        "indicators":    ["T1566", "spf=fail", "dkim=fail", "autoopen", "OpenAction", "T1137"],
        "base_confidence": 60,
    },
    {
        "name":          "Malicious Document / Macro Attack",
        "attack_type":   "Macro Malware",
        "family_hints":  ["Emotet", "Qakbot", "TrickBot", "Dridex"],
        "indicators":    ["AutoOpen", "Document_Open", "Shell", "CreateObject", "T1137"],
        "base_confidence": 65,
    },
    {
        "name":          "Persistence / Supply Chain Implant",
        "attack_type":   "Persistence",
        "family_hints":  ["Scheduled Task", "Registry Run Key", "DLL Hijack"],
        "indicators":    ["T1547", "T1053", "schtasks", "HKCU", "HKLM", "run"],
        "base_confidence": 55,
    },
    {
        "name":          "Lateral Movement / Worm",
        "attack_type":   "Lateral Movement",
        "family_hints":  ["PsExec", "WannaCry", "NotPetya"],
        "indicators":    ["T1021", "T1550", "psexec", "pass-the-hash", "smb"],
        "base_confidence": 55,
    },
]


def generate_hypothesis(report: DFIRReport) -> dict:
    """
    Infer the most likely attack scenario based on findings, MITRE techniques,
    and extracted evidence. Returns a hypothesis dict with confidence score.
    """
    if not has_forensic_evidence(report):
        return {
            "primary": "Insufficient forensic evidence",
            "attack_type": "None",
            "malware_family": "None",
            "confidence": 0,
            "reasoning": ["No actionable forensic indicators or signatures were extracted from the evidence."]
        }

    evidence_text_parts = []
    ev = report.extracted_evidence
    for k, v in ev.items():
        if isinstance(v, list):
            evidence_text_parts.extend(str(item) for item in v)
        elif isinstance(v, dict):
            evidence_text_parts.extend(f"{key}:{val}" for key, val in v.items())
        else:
            evidence_text_parts.append(str(v))

    all_evidence_text = " ".join(evidence_text_parts + [
        report.what_happened,
        " ".join(f.title + " " + f.detail for f in report.findings),
        " ".join(report.mitre_techniques),
    ]).lower()

    best_match: Optional[dict] = None
    best_score = 0
    best_reasoning: list[str] = []

    for profile in _HYPOTHESIS_PROFILES:
        score = profile["base_confidence"]
        reasoning: list[str] = []
        hits = 0

        for indicator in profile["indicators"]:
            if indicator.lower() in all_evidence_text:
                hits += 1
                reasoning.append(f"Matched indicator: '{indicator}'")

        score = min(96, profile["base_confidence"] + hits * 6)

        if report.risk_score >= 75:
            score = min(96, score + 10)
        elif report.risk_score >= 40:
            score = min(96, score + 5)

        if hits > 0 and score > best_score:
            best_score = score
            best_match = profile
            best_reasoning = reasoning

    if not best_match:
        return {
            "primary": "Undetermined — insufficient corroborating evidence",
            "attack_type": "Unknown",
            "malware_family": "Unknown",
            "confidence": max(10, report.risk_score // 2),
            "reasoning": ["No strong profile match found", "Analysis based on heuristic evidence only"]
        }

    return {
        "primary": best_match["name"],
        "attack_type": best_match["attack_type"],
        "malware_family": " / ".join(best_match["family_hints"][:3]),
        "confidence": best_score,
        "reasoning": best_reasoning[:6]
    }


def format_dfir_report_html_v2(report: DFIRReport, max_findings: int = 8) -> list[str]:
    """
    Format DFIRReport as Telegram HTML messages — full 12-section autonomous output.
    """
    import html as _h

    sep   = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
    dash  = "─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─"
    verdict_emoji = {
        "CONFIRMED THREAT": "🔴", "MALICIOUS": "🟠",
        "SUSPICIOUS": "🟡", "BENIGN": "🟢", "UNKNOWN": "⚪"
    }.get(report.verdict, "⚪")

    pages: list[str] = []
    hyp   = report.hypothesis or {}
    chain = report.attack_chain or []

    # ══ PAGE 1: Executive Summary ═════════════════════════════════════════════
    conf_bar = "█" * (hyp.get("confidence", 0) // 10) + "░" * (10 - hyp.get("confidence", 0) // 10)
    p1 = (
        f"🔬 <b>AUTONOMOUS DFIR INVESTIGATION REPORT</b>\n"
        f"<code>{sep}</code>\n"
        f"📁 <b>Case ID:</b>   <code>DFIR-{report.case_id}</code>\n"
        f"📄 <b>Evidence:</b>  <code>{_h.escape(report.evidence_name)}</code>\n"
        f"🗂 <b>Type:</b>      <code>{report.evidence_type} ({report.detected_type.upper()})</code>\n"
        f"🧬 <b>Entropy:</b>   <code>{report.entropy:.2f}/8.0</code>\n"
        f"🕒 <b>Analysed:</b>  <code>{report.started_at[:19]} UTC</code>\n"
        f"🤖 <b>Engine:</b>    <code>{_h.escape(report.investigator)}</code>\n"
        f"<code>{sep}</code>\n\n"
        f"{verdict_emoji} <b>VERDICT: {report.verdict}</b>\n"
        f"📊 <b>Risk Score:</b> <code>{report.risk_score}/100</code>\n"
        f"🎯 <b>Hypothesis:</b> <code>{_h.escape(hyp.get('primary', 'Undetermined'))}</code>\n"
        f"🔮 <b>Confidence:</b> <code>[{conf_bar}] {hyp.get('confidence', 0)}%</code>\n"
        f"🦠 <b>Malware Family:</b> <code>{_h.escape(hyp.get('malware_family', 'Unknown'))}</code>\n\n"
        f"<b>① EXECUTIVE SUMMARY</b>\n<code>{dash}</code>\n"
        f"{_h.escape(report.what_happened)}\n\n"
        f"<b>🚪 Initial Access:</b> {_h.escape(report.initial_access or 'Under investigation')}\n"
        f"<b>📅 When:</b> {_h.escape(report.when_happened)}\n"
        f"<b>🚚 Delivery:</b> {_h.escape(report.how_happened or 'Unknown')}\n"
    )
    pages.append(p1)

    # ══ PAGE 2: Key Findings + Evidence Breakdown ═════════════════════════════
    if report.findings:
        p2 = f"<b>② KEY FINDINGS ({len(report.findings)} total)</b>\n<code>{sep}</code>\n\n"
        for i, f in enumerate(report.findings[:max_findings], 1):
            p2 += (
                f"{f.severity_emoji} <b>{_h.escape(f.title)}</b>\n"
                f"  • <b>Evidence:</b> <code>{_h.escape(f.evidence or 'Heuristic pattern')}</code>\n"
                f"  • <b>Reasoning:</b> {_h.escape(f.reasoning or f.detail)}\n"
                f"  • <b>Confidence:</b> <code>{f.confidence}%</code>\n"
                f"  • <b>Alternative Explanation:</b> <tg-spoiler>{_h.escape(f.alternative_explanation or 'Standard benign operational behavior.')}</tg-spoiler>\n"
                f"  • <b>Recommended Action:</b> <code>{_h.escape(f.recommended_action or 'Investigate locally')}</code>\n"
            )
            if f.mitre:
                p2 += f"  🎯 <i>MITRE: {_h.escape(', '.join(f.mitre[:2]))}</i>\n"
            p2 += "\n"
        if len(report.findings) > max_findings:
            p2 += f"<i>… and {len(report.findings) - max_findings} more findings</i>\n"

        p2 += f"\n<b>③ EVIDENCE BREAKDOWN</b>\n<code>{sep}</code>\n"
        for e in report.evidence_summary[:8]:
            p2 += f"  • <code>{_h.escape(str(e))}</code>\n"
        pages.append(p2)

    # ══ PAGE 3: Timeline + MITRE Mapping ═════════════════════════════════════
    p3 = f"<b>④ TIMELINE OF EVENTS</b>\n<code>{sep}</code>\n"
    if report.attack_timeline:
        for entry in report.attack_timeline[:8]:
            t  = _h.escape(str(entry.get("time", "?"))[:26])
            ev = _h.escape(str(entry.get("event", ""))[:110])
            p3 += f"  <code>[{t}]</code> {ev}\n"
    else:
        p3 += "  <i>No timeline events recorded</i>\n"

    if report.mitre_techniques:
        p3 += f"\n<b>⑥ MITRE ATT&amp;CK MAPPING</b>\n<code>{sep}</code>\n"
        for t in report.mitre_techniques[:12]:
            p3 += f"  • <code>{_h.escape(t)}</code>\n"
    pages.append(p3)

    # ══ PAGE 4: IOC List ══════════════════════════════════════════════════════
    iocs = report.extracted_iocs
    total_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))
    p4 = f"<b>⑤ IOC LIST ({total_iocs} total)</b>\n<code>{sep}</code>\n\n"
    if iocs.get("ips"):
        p4 += f"<b>🌐 IPs ({len(iocs['ips'])}):</b>\n"
        for ip in iocs["ips"][:8]:
            p4 += f"  <code>{_h.escape(ip)}</code>\n"
    if iocs.get("domains"):
        p4 += f"\n<b>🔗 Domains ({len(iocs['domains'])}):</b>\n"
        for d in iocs["domains"][:8]:
            p4 += f"  <code>{_h.escape(d)}</code>\n"
    if iocs.get("urls"):
        p4 += f"\n<b>🌍 URLs ({len(iocs['urls'])}):</b>\n"
        for u in iocs["urls"][:5]:
            p4 += f"  <code>{_h.escape(u[:80])}</code>\n"
    if iocs.get("hashes"):
        p4 += f"\n<b>🔒 Hashes ({len(iocs['hashes'])}):</b>\n"
        for h in iocs["hashes"][:5]:
            p4 += f"  <code>{_h.escape(h[:48])}…</code>\n"
    if iocs.get("emails"):
        p4 += f"\n<b>📧 Emails ({len(iocs['emails'])}):</b>\n"
        for em in iocs["emails"][:5]:
            p4 += f"  <code>{_h.escape(em)}</code>\n"
    if total_iocs == 0:
        p4 += "<i>No IOCs extracted from this artifact.</i>\n"
    pages.append(p4)
    if report.evidence_type == "PCAP":
        p_net = f"<b>🌐 PCAP NETWORK TRAFFIC INTELLIGENCE</b>\n<code>{sep}</code>\n\n"
        
        talkers = report.network_analytics.get("top_talkers", [])
        if talkers:
            p_net += "<b>👥 TOP TALKERS (Ranked by Bytes)</b>\n"
            p_net += "<code>IP Address      | Conns | Bytes     | Role (Score)</code>\n"
            p_net += f"<code>{dash}</code>\n"
            for t in talkers[:8]:
                ip_str = t["ip"].ljust(15)[:15]
                conns = str(t["connections"]).rjust(5)
                bytes_trans = t["bytes_transferred"]
                if bytes_trans >= 1024 * 1024:
                    bytes_str = f"{bytes_trans / (1024 * 1024):.1f}MB".rjust(9)
                elif bytes_trans >= 1024:
                    bytes_str = f"{bytes_trans / 1024:.1f}KB".rjust(9)
                else:
                    bytes_str = f"{bytes_trans}B".rjust(9)
                
                role_str = f"{t['role']} ({t['score']})"
                p_net += f"<code>{ip_str} | {conns} | {bytes_str} | {role_str}</code>\n"
            p_net += "\n"
        
        ports = report.network_analytics.get("port_breakdown", {})
        if ports:
            p_net += "<b>🔌 PORT BREAKDOWN & TRAFFIC VOLUME</b>\n"
            sorted_ports = sorted(ports.items(), key=lambda x: x[1], reverse=True)
            p_net += "  • " + ", ".join(f"Port {port} ({count} pkts)" for port, count in sorted_ports[:6]) + "\n"
            
            alerts = []
            for t in talkers:
                if t["score"] >= 30:
                    alerts.append(f"IP {t['ip']} flagged as {t['classification']} (Score: {t['score']}/100)")
            if alerts:
                p_net += "⚠️ <b>Network Alerts:</b>\n"
                for alert in alerts[:3]:
                    p_net += f"  • {alert}\n"
            p_net += "\n"

        credentials = report.network_analytics.get("credentials", [])
        if credentials:
            p_net += "<b>🔑 MINED LOGIN CREDENTIALS</b>\n"
            for cred in credentials[:5]:
                p_net += f"  • <code>[{_h.escape(cred['proto'])}]</code> <b>{_h.escape(cred['ip'])}</b>: <code>{_h.escape(cred['credential'])}</code>\n"
            p_net += "\n"

        beacons = report.network_analytics.get("beaconing_sessions", [])
        if beacons:
            p_net += "<b>🚨 BEACONING PERIODICITY DETECTION</b>\n"
            for b in beacons[:5]:
                p_net += f"  • Target: <b>{_h.escape(b['target_ip'])}</b> | Interval: <code>{b['interval']}</code> | Confidence: <code>{b['confidence']}</code>\n"
        
        pages.append(p_net)


    # ══ PAGE 5: Correlation Graph + Attack Reconstruction ════════════════════
    p5 = f"<b>⑦ CORRELATION GRAPH SUMMARY</b>\n<code>{sep}</code>\n"
    corr = report.correlation_graph
    if corr:
        for pivot, targets in list(corr.items())[:5]:
            p5 += f"  🔗 <code>{_h.escape(str(pivot)[:40])}</code> → "
            p5 += ", ".join(f"<code>{_h.escape(str(t)[:30])}</code>" for t in (targets[:3] if isinstance(targets, list) else [str(targets)]))
            p5 += "\n"
    else:
        p5 += "  <i>Single artifact — cross-evidence correlation requires multiple files</i>\n"

    p5 += f"\n<b>⑨ ATTACK RECONSTRUCTION</b>\n<code>{sep}</code>\n"
    confirmed_phases = [c for c in chain if c["status"] == "CONFIRMED"]
    inferred_phases  = [c for c in chain if c["status"] == "INFERRED"]

    if confirmed_phases:
        p5 += f"<b>🔴 CONFIRMED phases ({len(confirmed_phases)}):</b>\n"
        for phase in confirmed_phases:
            p5 += (
                f"  ✅ <b>{_h.escape(phase['phase'])}</b> "
                f"[{phase['confidence']}%]\n"
            )
            if phase["evidence"]:
                p5 += f"     └ {_h.escape(phase['evidence'][0][:70])}\n"

    if inferred_phases[:3]:
        p5 += f"<b>🟡 INFERRED phases (likely):</b>\n"
        for phase in inferred_phases[:3]:
            p5 += f"  🔍 {_h.escape(phase['phase'])}\n"
    pages.append(p5)

    # ══ PAGE 6: TI Summary + Hypothesis ══════════════════════════════════════
    p6 = f"<b>⑧ THREAT INTELLIGENCE SUMMARY</b>\n<code>{sep}</code>\n"
    ti = report.ti_enrichment
    if ti:
        for ioc_val, ti_data in list(ti.items())[:6]:
            score = ti_data.get("abuse_score") or ti_data.get("vt_mal") or "N/A"
            p6 += f"  <code>{_h.escape(str(ioc_val)[:40])}</code> → Score: {score}\n"
    else:
        p6 += "  <i>TI enrichment runs post-analysis. Use /check on individual IOCs.</i>\n"

    p6 += f"\n<b>⑩ HYPOTHESIS &amp; CONFIDENCE SCORE</b>\n<code>{sep}</code>\n"
    p6 += f"  <b>Primary:</b> {_h.escape(hyp.get('primary', 'Undetermined'))}\n"
    p6 += f"  <b>Type:</b> {_h.escape(hyp.get('attack_type', 'Unknown'))}\n"
    p6 += f"  <b>Family:</b> <code>{_h.escape(hyp.get('malware_family', 'Unknown'))}</code>\n"
    p6 += f"  <b>Confidence:</b> <code>{hyp.get('confidence', 0)}%</code>\n"
    if hyp.get("reasoning"):
        p6 += "  <b>Reasoning:</b>\n"
        for r in hyp["reasoning"][:4]:
            p6 += f"    • {_h.escape(r)}\n"
    pages.append(p6)

    # ══ PAGE 7: Attacker Actions + Recommended Actions ═══════════════════════
    p7 = ""
    if report.attacker_actions:
        p7 += f"<b>👤 ATTACKER ACTIONS</b>\n<code>{sep}</code>\n"
        for a in report.attacker_actions[:6]:
            p7 += f"  • {_h.escape(a)}\n"
        p7 += "\n"
    if report.affected_systems:
        p7 += f"<b>🖥 AFFECTED SYSTEMS</b>\n<code>{sep}</code>\n"
        for s in report.affected_systems[:5]:
            p7 += f"  • {_h.escape(s)}\n"
        p7 += "\n"
    if report.next_steps:
        p7 += f"<b>⑪ RECOMMENDED ANALYST ACTIONS</b>\n<code>{sep}</code>\n"
        for s in report.next_steps[:8]:
            p7 += f"  {_h.escape(s)}\n"
    if p7:
        pages.append(p7)

    # ══ PAGE 8: Containment & Response Plan ══════════════════════════════════
    if report.containment:
        p8 = f"<b>⑫ CONTAINMENT &amp; RESPONSE PLAN</b>\n<code>{sep}</code>\n"
        for c in report.containment:
            p8 += f"  {_h.escape(c)}\n"
        p8 += (
            f"\n<code>{sep}</code>\n"
            f"<i>🔬 DFIR-{report.case_id} | {_h.escape(report.investigator)} | "
            f"Auto-executed on upload</i>"
        )
        pages.append(p8)

    # ══ PAGE 9: Verbose Analyst Mode Reasoning Steps ════════════════════════
    if report.analyst_mode_logs:
        p9 = f"<b>🧐 ANALYST MODE: DECISION EXPLANATIONS</b>\n<code>{sep}</code>\n\n"
        p9 += "👁 <b>Tap/Click to expand reasoning log:</b>\n"
        logs_str = "\n".join(f"  • {log}" for log in report.analyst_mode_logs)
        p9 += f"<tg-spoiler>{_h.escape(logs_str)}</tg-spoiler>"
        pages.append(p9)

    return pages


def analyze_file_dfir_path(
    filepath: str,
    filename: str,
    file_type: str,
    metadata: dict,
    anomalies: list[str],
    vt_result: dict,
    mb_result: dict,
) -> DFIRReport:
    """
    Produce a full DFIR investigation report from a file path.
    If the file exceeds config.MAX_FILE_SIZE_MB, switches to Large Forensic Mode
    and uses the streaming engine to avoid OOM errors. Otherwise, reads the file
    into memory and delegates to the standard analyze_file_dfir.
    """
    import os
    import config
    import dfir_streaming
    
    try:
        file_size = os.path.getsize(filepath)
    except Exception as e:
        logger.error(f"Failed to get file size for {filepath}: {e}")
        file_size = 0

    max_bytes = config.MAX_FILE_SIZE_MB * 1024 * 1024
    
    # Read first 512 bytes for case ID
    first_512 = b""
    try:
        with open(filepath, "rb") as f:
            first_512 = f.read(512)
    except Exception as e:
        logger.error(f"Failed to read file header: {e}")

    case_id = hashlib.md5(first_512).hexdigest()[:8].upper()
    
    # Standard or Large Forensic Mode?
    if file_size > max_bytes:
        logger.info(f"File size {file_size} exceeds {max_bytes} bytes. Switching to Large Forensic Mode.")
        report = DFIRReport(
            case_id=case_id,
            evidence_type="FILE",
            evidence_name=filename,
        )
        report.detected_type = file_type
        
        # Stream-hash the file
        sha256_hash = hashlib.sha256()
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        try:
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(64 * 1024)
                    if not chunk:
                        break
                    sha256_hash.update(chunk)
                    md5_hash.update(chunk)
                    sha1_hash.update(chunk)
            sha256 = sha256_hash.hexdigest()
            md5 = md5_hash.hexdigest()
        except Exception as e:
            logger.error(f"Failed to hash large file: {e}")
            sha256 = ""
            md5 = ""
            
        report.evidence_summary.append(f"File: {filename} ({file_size/(1024*1024):.1f} MB, {file_type.upper()}) [Large Forensic Mode]")
        if sha256:
            report.evidence_summary.append(f"SHA-256: {sha256}")
            report.evidence_summary.append(f"MD5:     {md5}")
            
        # Add TI findings if available
        vt_res = vt_result
        mb_res = mb_result
        
        vt_mal = vt_res.get("malicious", 0) if vt_res and "error" not in vt_res else 0
        vt_total = (vt_res.get("harmless", 0) + vt_res.get("undetected", 0) +
                    vt_res.get("suspicious", 0) + vt_mal) if vt_res and "error" not in vt_res else 0
        vt_label = vt_res.get("threat_label", "") if vt_res else ""

        if vt_mal > 0:
            severity = "CRITICAL" if vt_mal >= 10 else "HIGH" if vt_mal >= 3 else "MEDIUM"
            report.add_finding(
                category="FILE",
                severity=severity,
                title=f"VirusTotal: {vt_mal}/{vt_total} Engines Detected Malware",
                detail=f"Threat label: {vt_label or 'Unknown'}. File is confirmed malicious by {vt_mal} AV engines.",
                evidence=f"SHA-256: {sha256[:32]}…",
                mitre=["T1204.002 – Malicious File"]
            )
            report.initial_access = "Malicious file delivery (T1204.002 – User Execution: Malicious File)"
            report.what_happened = f"A malicious file was identified: {filename}. It was flagged by {vt_mal}/{vt_total} antivirus engines on VirusTotal with threat classification: {vt_label or 'Unclassified'}."
        elif vt_total > 0:
            report.add_finding("FILE", "INFO", "VirusTotal: No Detections",
                               f"Scanned by {vt_total} engines — no malicious detections found.", evidence=f"MD5: {md5}")
            report.what_happened = f"File '{filename}' was scanned across {vt_total} AV engines with no detections. File appears benign based on signature analysis."

        if mb_res and mb_res.get("found"):
            sig = mb_res.get("signature", "Unknown")
            ftype_mb = mb_res.get("file_type", "Unknown")
            first_seen = mb_res.get("first_seen", "Unknown")
            report.add_finding(
                category="FILE", severity="CRITICAL",
                title=f"MalwareBazaar: Known Malware — {sig}",
                detail=f"File matches a known malware sample in MalwareBazaar database. "
                       f"Signature: {sig}, Type: {ftype_mb}, First Seen: {first_seen}.",
                evidence=f"SHA-256: {sha256[:32]}…",
                mitre=["T1204.002 – Malicious File"]
            )
            report.evidence_summary.append(f"MalwareBazaar: MATCHED — {sig} (First seen: {first_seen})")
            report.what_happened = f"File '{filename}' is a known malware sample. Signature: {sig}. " \
                                   f"First observed in the wild: {first_seen}."
        
        # Route to streaming engine
        dfir_streaming.analyze_file_large(filepath, filename, file_type, report)
        
        # Add timeline, inference, etc.
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        if not report.attack_timeline:
            report.attack_timeline = []
        report.attack_timeline.insert(0, {"time": "T+0", "event": f"File '{filename}' received for autonomous DFIR analysis"})
        report.attack_timeline.append({"time": now_str, "event": f"Analysis complete — {len(report.findings)} findings, risk {report.risk_score}/100"})
        if mb_res and mb_res.get("found"):
            first_seen = mb_res.get("first_seen", "Unknown")
            report.attack_timeline.insert(0, {
                "time": first_seen,
                "event": f"First seen in the wild (MalwareBazaar) — {mb_res.get('signature', 'Unknown')}",
            })
        _sort_timeline(report)
        
        report.when_happened = now_str
        if not report.what_happened:
            report.what_happened = (
                f"File '{filename}' automatically submitted to the DFIR Execution Engine in Large Forensic Mode. "
                f"Type: {file_type.upper()}, Size: {file_size/(1024*1024):.1f} MB."
            )
            
        report.how_happened = _infer_delivery_method(file_type, anomalies, mb_res)
        report.attacker_actions = _infer_attacker_actions(file_type, report.findings,
                                                           report.extracted_iocs, anomalies)
        report.affected_systems = _infer_affected_systems(file_type, anomalies)
        report.next_steps = _generate_next_steps(report)
        report.containment = _generate_containment(report)
        correlate_evidence(report)
        report.attack_chain = reconstruct_attack_chain(report)
        report.hypothesis = generate_hypothesis(report)
        
        report.finalize()
        return report
    else:
        # File is small enough to load into memory
        try:
            with open(filepath, "rb") as f:
                file_bytes = f.read()
        except Exception as e:
            logger.error(f"Failed to read file {filepath} to memory: {e}")
            file_bytes = b""
            
        return analyze_file_dfir(
            file_bytes=file_bytes,
            filename=filename,
            file_type=file_type,
            metadata=metadata,
            anomalies=anomalies,
            vt_result=vt_result,
            mb_result=mb_result,
        )


def analyze_file_dfir_metadata_only(
    filename: str,
    file_size: int,
    file_type: str,
) -> DFIRReport:
    """
    Generate a full DFIR report based only on file metadata when download is blocked
    by Telegram Bot API limits (Public Server Mode).
    """
    case_id = hashlib.md5(filename.encode()).hexdigest()[:8].upper()
    report = DFIRReport(
        case_id=case_id,
        evidence_type="FILE",
        evidence_name=filename,
    )
    report.detected_type = file_type
    report.entropy = 0.0
    
    report.evidence_summary.append(
        f"File: {filename} ({file_size/(1024*1024):.1f} MB, {file_type.upper()}) [Download Blocked by Telegram API limits]"
    )
    report.evidence_summary.append("Notice: Analysis performed using Static Profile & Metadata Heuristics.")

    report.add_finding(
        category="FILE", severity="HIGH",
        title="Evidence Analysis Strategy Adjusted: Metadata & Static Profile Mode",
        detail=f"The uploaded file exceeds the download limit (20MB) of Telegram's public Bot API servers. "
               f"To ensure analysis availability without blocking the workflow, the engine switched to "
               f"Static Profile Mode. Security teams should inspect the raw file on the endpoint using the recommended actions.",
        evidence=f"File size: {file_size/(1024*1024):.1f} MB"
    )

    # Add generic findings based on file type
    if file_type in ("pcap", "pcapng"):
        report.add_finding(
            category="NETWORK", severity="HIGH",
            title="Large PCAP Analysis Profile: Network Triage Required",
            detail="Large packet captures typically contain command and control (C2) beaconing, network sweeps, "
                   "lateral movement via SMB/WMI, or data exfiltration. Static profile suggests querying DNS queries "
                   "and HTTP hosts immediately using local tools.",
            mitre=["T1071 – Application Layer Protocol", "T1041 – Exfiltration over C2"]
        )
        report.initial_access = "Spearphishing or Exploit delivery (Static Profile Heuristics)"
        report.what_happened = f"Large network capture '{filename}' submitted. Due to Telegram API download limits, metadata-only profiling was performed."
    elif file_type in ("memory", "raw", "dmp"):
        report.add_finding(
            category="MEMORY", severity="HIGH",
            title="Large Memory Dump Profile: Process & Signature Triage Required",
            detail="Memory images are highly rich sources of active process listings, DLL injections, "
                   "and credential harvesting artifacts (e.g. LSASS dumps, Mimikatz traces). Static profile suggests "
                   "running volatility3 tools locally.",
            mitre=["T1003.001 – LSASS Memory Dump", "T1055 – Process Injection"]
        )
        report.initial_access = "System Compromise / Execution (Static Profile Heuristics)"
        report.what_happened = f"Large system memory image '{filename}' submitted. Profiling suggests scanning for process execution and credentials."
    elif file_type == "disk":
        report.add_finding(
            category="FILE", severity="HIGH",
            title="Large Disk Image Profile: Partition & File Recovery Triage Required",
            detail="Disk images contain partition tables, MFT/inode structures, registry databases, and persistent "
                   "autostart locations (run keys, scheduled tasks). Static profile suggests mounting or carving with TSK tools.",
            mitre=["T1547.001 – Registry Run Keys", "T1053.005 – Scheduled Task"]
        )
        report.initial_access = "Persistence / Defense Evasion (Static Profile Heuristics)"
        report.what_happened = f"Large forensic disk image '{filename}' submitted. Profiling suggests registry and partition carving."
    else:
        report.add_finding(
            category="FILE", severity="MEDIUM",
            title="Large File Profile: Generic Threat Triage Required",
            detail="The file has been profiled based on size and type. Analyze strings and calculate entropy locally.",
            mitre=["T1204.002 – Malicious File"]
        )
        report.what_happened = f"Large file '{filename}' submitted. Switched to static triage mode."

    # Build timeline, next steps, etc.
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    report.attack_timeline = [
        {"time": "T+0", "event": f"File '{filename}' metadata registered by DFIR Engine"},
        {"time": now_str, "event": "Analysis completed in Static Profile Mode"}
    ]
    report.when_happened = now_str
    
    # Simple delivery, actions, next steps
    report.how_happened = f"File type suggests standard delivery vector for {file_type.upper()} evidence."
    report.attacker_actions = [f"[HIGH] Potential execution/C2 activities related to {file_type.upper()} artifacts"]
    report.affected_systems = ["Local endpoint/server housing the original evidence"]
    
    # Generate recommendations
    report.next_steps = [
        f"✅ Copy the file locally and extract MD5/SHA256 hashes",
        f"✅ Run local forensic suite (Wireshark for PCAP, Volatility for Memory, SleuthKit for Disk)",
        f"✅ Search SIEM for host/IP entities referenced in case name",
    ]
    report.containment = [
        f"⚠️ High Priority: Verify file integrity and block any related endpoints locally",
    ]
    
    report.attack_chain = reconstruct_attack_chain(report)
    report.hypothesis = generate_hypothesis(report)
    
    report.finalize()
    return report
