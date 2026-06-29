"""
dfir_streaming.py - Streaming and Memory-Mapped Forensic Analysis Engines

Enables multi-GB forensic file analysis without full RAM loading.
Uses mmap for memory dumps and block-by-block streaming for PCAPs/Disk images.
"""
from __future__ import annotations

import io
import os
import re
import mmap
import math
import struct
import logging
import zipfile
import urllib.parse
import base64
from datetime import datetime, timezone
from pathlib import Path

import dpkt
import dfir_engine as dfir
from dfir_engine import DFIRReport, DFIRFinding

logger = logging.getLogger(__name__)

# Heuristics & Signatures
_PRIV = ("127.", "0.", "10.", "192.168.", "172.")
_SUSPICIOUS_UA_SIGS = ["sqlmap", "nmap", "nikto", "hydra", "dirbuster", "gobuster", "w3af", "metasploit", "nessus", "netsparker", "acunetix"]

# Common RAM processes
_MEMORY_PROCESS_PATTERNS = [
    re.compile(b"[a-zA-Z0-9_\\-]{3,15}\\.(?:exe|dll|sys)", re.IGNORECASE)
]

# Malware indicators inside memory or disk strings
_MALWARE_STRINGS = [
    (b"mimikatz", "Mimikatz Credential Tool", "T1003.001"),
    (b"sekurlsa", "Mimikatz sekurlsa Module", "T1003.001"),
    (b"privilege::debug", "LSASS Privilege Escalation", "T1134"),
    (b"cobaltstrike", "Cobalt Strike Beacon", "T1071.001"),
    (b"meterpreter", "Metasploit Meterpreter Shell", "T1071"),
    (b"vssadmin delete", "Inhibit System Recovery (Ransomware)", "T1490"),
    (b"bcdedit /set", "Inhibit Boot Configuration Recovery", "T1490"),
    (b"psexec", "Sysinternals PsExec Tool", "T1021.002"),
    (b"lsass.dump", "LSASS Process Dumping", "T1003.001"),
    (b"inject.bin", "Process Injection Payload", "T1055"),
]


# ═══════════════════════════════════════════════════════════════════════════════
# PCAP STREAMING ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def _extract_pcap_streaming_evidence(filepath: str) -> tuple[dict, dict]:
    import dpkt
    import base64
    import urllib.parse
    import os
    from collections import defaultdict
    import logging

    logger = logging.getLogger(__name__)

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
        f = open(filepath, "rb")
    except Exception as e:
        logger.error(f"Failed to open PCAP file: {e}")
        return extracted, analytics

    try:
        try:
            pcap_file = dpkt.pcap.Reader(f)
        except Exception:
            f.seek(0)
            try:
                pcap_file = dpkt.pcapng.Reader(f)
            except Exception as e:
                logger.warning(f"dpkt streaming PCAP open failed: {e}")
                f.close()
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

        logger.info(f"[STREAM] packet parser started for {filepath}")
        for ts, pkt in pcap_file:
            pkt_count += 1
            if pkt_count in (1000, 10000, 50000, 100000):
                logger.info(f"[STREAM] packet count milestone: {pkt_count}")
            if pkt_count > 50000:
                if pkt_count % 10 != 0:
                    continue # Process only every 10th packet
            if pkt_count > 200000:
                logger.info(f"[STREAM] reached packet cap (200,000). Stopping early.")
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
                            http_req = dpkt.http.Request(tcp.data)
                            host = http_req.headers.get("host", "")
                            if host:
                                http_hosts.append(host)
                            
                            uri = http_req.uri
                            extracted["urls"].append(f"{http_req.method} {host}{uri}")

                            # Basic Authentication extractor
                            auth = http_req.headers.get("authorization", "")
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
                            body = http_req.body
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
                                        "proto": f"HTTP-POST ({http_req.method})",
                                        "src": src, "dst": dst,
                                        "user": found_user or "[Not Found]",
                                        "pass": found_pass or "[Not Found]"
                                    })
                                    ip_stats[src]["login_attempts"] += 1

                            # Heuristics for common web vulnerabilities (SQLi, Directory Traversal, XSS)
                            uri_dec = urllib.parse.unquote(http_req.uri)
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
                            ua = http_req.headers.get("user-agent", "")
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
    finally:
        f.close()

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
    from dfir_engine import _detect_beaconing
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


def _extract_pcap_heuristic_stream(filepath: str) -> tuple[dict, dict]:
    ip_pattern  = re.compile(b"\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b")
    url_pattern = re.compile(b"https?://[a-zA-Z0-9_\\-\\.\\/\\?&%=]+")
    
    ips:  set[str] = set()
    urls: set[str] = set()
    
    block_size = 128 * 1024 # 128KB
    _PRIV = ("127.", "0.", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")

    try:
        with open(filepath, "rb") as f:
            while True:
                block = f.read(block_size)
                if not block:
                    break
                
                # IPs
                for match in ip_pattern.finditer(block):
                    ip = match.group().decode("latin-1")
                    if not any(ip.startswith(p) for p in _PRIV):
                        ips.add(ip)
                        if len(ips) > 50:
                            break
                
                # URLs
                for match in url_pattern.finditer(block):
                    url = match.group().decode("latin-1")
                    if not any(p in url for p in _PRIV) and "adobe" not in url and "w3.org" not in url:
                        urls.add(url)
                        if len(urls) > 50:
                            break
                            
                if len(ips) > 50 and len(urls) > 50:
                    break
    except Exception as e:
        logger.warning(f"PCAP heuristic stream scan failed: {e}")

    extracted = {
        "ips": list(ips),
        "domains": [urllib.parse.urlparse(u).netloc for u in urls if u],
        "urls": list(urls),
        "emails": [],
        "hashes": [],
        "network_flows": [],
        "credentials": [],
        "metadata": [f"Heuristic PCAP stream file: {os.path.basename(filepath)}"],
        "others": ["Heuristic streaming parsing mode only"]
    }
    
    top_talkers = []
    for ip in list(ips)[:10]:
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


def analyze_pcap_streaming(filepath: str, report: DFIRReport):
    "Memory-efficient PCAP streaming analysis."
    _slog = logging.getLogger(__name__)
    _slog.info(f"[STREAM] entered analyze_pcap_streaming(filepath={filepath!r})")
    report.evidence_type = "PCAP"
    report.initial_access = "Network traffic capture (Large File Mode) - streaming packets for C2, credentials, and attacks"
    filename = os.path.basename(filepath)

    # 1. Evidence Extraction
    _slog.info(f"[STREAM] calling _extract_pcap_streaming_evidence()...")
    extracted, analytics = _extract_pcap_streaming_evidence(filepath)
    _slog.info(
        f"[STREAM] _extract_pcap_streaming_evidence() returned: "
        f"IPs={len(extracted['ips'])}, domains={len(extracted['domains'])}, "
        f"urls={len(extracted['urls'])}, flows={len(extracted['network_flows'])}, "
        f"credentials={len(extracted['credentials'])}"
    )

    if not extracted["ips"] and not extracted["urls"]:
        _slog.warning(f"[STREAM] No IPs or URLs found via dpkt. Falling back to heuristic stream parser.")
        extracted, analytics = _extract_pcap_heuristic_stream(filepath)
        _slog.info(
            f"[STREAM] heuristic fallback returned: IPs={len(extracted['ips'])}, "
            f"urls={len(extracted['urls'])}"
        )
    else:
        _slog.info(f"[STREAM] dpkt extraction succeeded. Skipping heuristic fallback.")
        
    report.extracted_evidence.update(extracted)
    report.network_analytics.update(analytics)

    # Merge IOCs
    report.extracted_iocs["ips"] = list(set(report.extracted_iocs.get("ips", []) + extracted["ips"]))[:20]
    report.extracted_iocs["domains"] = list(set(report.extracted_iocs.get("domains", []) + extracted["domains"]))[:20]
    report.extracted_iocs["urls"] = list(set(report.extracted_iocs.get("urls", []) + extracted["urls"]))[:20]

    # 2. Findings Analysis
    _slog.info(f"[STREAM] calling _analyze_pcap_extracted_evidence()...")
    import dfir_engine as dfir
    dfir._analyze_pcap_extracted_evidence(report)
    _slog.info(f"[STREAM] findings after analysis: {len(report.findings)}")

    report.attack_timeline.append({
        "time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "event": f"PCAP streaming analysed: {len(extracted['network_flows'])} flows, {len(extracted['ips'])} ext IPs, {len(extracted['domains'])} DNS/Hosts"
    })
    _slog.info(f"[STREAM] analyze_pcap_streaming() complete.")


def _analyze_pcap_heuristic_stream(filepath: str, report: DFIRReport):
    "Fallback streaming heuristic file scan."
    report.evidence_summary.append("PCAP: Streaming in Heuristic Mode (dpkt parsing failed).")
    extracted, analytics = _extract_pcap_heuristic_stream(filepath)
    report.extracted_evidence.update(extracted)
    report.network_analytics.update(analytics)
    import dfir_engine as dfir
    dfir._analyze_pcap_extracted_evidence(report)


def analyze_memory_streaming(filepath: str, report: DFIRReport):
    """Memory-mapped streaming analysis of RAW/DMP memory images."""
    _mlog = logging.getLogger(__name__)
    _mlog.info(f"[STREAM] entered analyze_memory_streaming(filepath={filepath!r})")
    report.evidence_type = "MEMORY"
    report.initial_access = "System RAM snapshot (Large File Mode) — scanning mapped memory for processes and malware"
    filename = os.path.basename(filepath)

    found_processes = set()
    found_malware = []
    ips = set()
    urls = set()

    ip_pattern  = re.compile(b"\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b")
    url_pattern = re.compile(b"https?://[a-zA-Z0-9_\\-\\.\\/\\?&%=]+")

    try:
        with open(filepath, "rb") as f:
            file_size = os.path.getsize(filepath)
            _mlog.info(f"[STREAM] memory file size: {file_size/(1024*1024):.1f} MB — opening mmap...")
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                _mlog.info(f"[STREAM] mmap opened. Scanning for process patterns...")
                for pat in _MEMORY_PROCESS_PATTERNS:
                    count = 0
                    for match in pat.finditer(mm):
                        found_processes.add(match.group().decode("latin-1", errors="ignore").lower())
                        count += 1
                        if count > 1000:
                            break
                _mlog.info(f"[STREAM] process scan complete: {len(found_processes)} unique process names found")

                _mlog.info(f"[STREAM] scanning for malware signatures ({len(_MALWARE_STRINGS)} signatures)...")
                for word, label, mitre_id in _MALWARE_STRINGS:
                    pos = mm.find(word)
                    if pos != -1:
                        w_str = word.decode()
                        _mlog.info(f"[STREAM] malware signature hit: {label!r} at offset {pos}")
                        if w_str in ("mimikatz", "sekurlsa", "lsass.dump"):
                            report.extracted_evidence["credentials"].append(f"Memory signature: {label} ({w_str})")
                        elif w_str in ("vssadmin delete", "bcdedit /set"):
                            report.extracted_evidence["persistence"].append(f"Memory signature: {label} ({w_str})")
                        else:
                            report.extracted_evidence["others"].append(f"Memory signature: {label} ({w_str})")

                scan_limit = min(file_size, 200 * 1024 * 1024)
                chunk = mm[:scan_limit]
                _mlog.info(f"[STREAM] scanning {scan_limit//1024//1024}MB for IPs and URLs...")

                ip_count = 0
                for match in ip_pattern.finditer(chunk):
                    ip = match.group().decode("latin-1")
                    if not any(ip.startswith(p) for p in _PRIV):
                        ips.add(ip)
                        ip_count += 1
                        if ip_count > 100:
                            break

                url_count = 0
                for match in url_pattern.finditer(chunk):
                    url = match.group().decode("latin-1")
                    if not any(p in url for p in _PRIV) and "adobe" not in url and "w3.org" not in url:
                        urls.add(url)
                        url_count += 1
                        if url_count > 100:
                            break

                _mlog.info(f"[STREAM] network IOC scan complete: IPs={len(ips)}, URLs={len(urls)}")
    except Exception as e:
        logger.warning(f"Memory mapped streaming failed: {e}")
        file_size = 0

    report.extracted_evidence["metadata"].append(f"Memory Artifact: {filename} ({file_size/(1024*1024):.1f} MB)")
    if found_processes:
        report.extracted_evidence["processes"].extend(list(found_processes))
    if ips:
        report.extracted_evidence["ips"].extend(list(ips))
        report.extracted_iocs["ips"] = list(set(report.extracted_iocs.get("ips", []) + list(ips)))[:20]
    if urls:
        report.extracted_evidence["urls"].extend(list(urls))
        report.extracted_iocs["urls"] = list(set(report.extracted_iocs.get("urls", []) + list(urls)))[:20]
        import urllib.parse
        domains = list(set([urllib.parse.urlparse(u).netloc for u in urls if u]))
        report.extracted_evidence["domains"].extend(domains)
        report.extracted_iocs["domains"] = list(set(report.extracted_iocs.get("domains", []) + domains))[:20]

    _mlog.info(
        f"[STREAM] evidence summary: processes={len(found_processes)}, "
        f"credentials={len(report.extracted_evidence.get('credentials',[]))}, "
        f"malware_sigs={len(report.extracted_evidence.get('others',[]))}, "
        f"IPs={len(ips)}, URLs={len(urls)}"
    )
    _mlog.info(f"[STREAM] calling _analyze_memory_evidence()...")
    dfir._analyze_memory_evidence(report)
    _mlog.info(f"[STREAM] analyze_memory_streaming() complete. findings={len(report.findings)}")


def analyze_disk_streaming(filepath: str, report: DFIRReport):
    """Streaming analysis of Disk Images (.dd, .img, .e01) without mounting."""
    report.evidence_type = "DISK"
    report.initial_access = "Forensic disk image (Large File Mode) — carving partition tables and registry files"
    filename = os.path.basename(filepath)
    file_size = os.path.getsize(filepath)

    filesystem_types = []
    found_windows_registry = False

    block_size = 64 * 1024
    entropies = []
    block_count = 0

    try:
        with open(filepath, "rb") as f:
            header = f.read(2 * 1024 * 1024)
            if b"NTFS" in header:
                filesystem_types.append("NTFS (Windows)")
            if b"FAT16" in header or b"FAT32" in header or b"MSDOS" in header:
                filesystem_types.append("FAT (Windows/Legacy)")
            if b"\\x53\\xef" in header[1024:2048]:
                filesystem_types.append("ext2/3/4 (Linux)")
            if b"EFI PART" in header:
                filesystem_types.append("GPT Partition Table")

            if b"regf" in header:
                found_windows_registry = True

            f.seek(0)
            while True:
                block = f.read(block_size)
                if not block:
                    break
                block_count += 1
                
                if block_count % 160 == 0:
                    entropies.append(_calculate_entropy_block(block))
                
                for word, label, mitre_id in _MALWARE_STRINGS:
                    if word in block:
                        w_str = word.decode()
                        if w_str in ("mimikatz", "sekurlsa", "lsass.dump"):
                            report.extracted_evidence["credentials"].append(f"Carved signature: {label} ({w_str})")
                        elif w_str in ("vssadmin delete", "bcdedit /set"):
                            report.extracted_evidence["persistence"].append(f"Carved signature: {label} ({w_str})")
                        else:
                            report.extracted_evidence["others"].append(f"Carved signature: {label} ({w_str})")
                
                if b"regf" in block:
                    found_windows_registry = True

                if block_count > 10000:
                    try:
                        f.seek(-1024 * 1024, os.SEEK_END)
                        end_block = f.read()
                        if b"regf" in end_block:
                            found_windows_registry = True
                    except Exception:
                        pass
                    break
    except Exception as e:
        logger.warning(f"Disk streaming analysis failed: {e}")

    avg_entropy = sum(entropies)/len(entropies) if entropies else 0.0
    
    report.extracted_evidence["metadata"].append(f"Disk Image: {filename} ({file_size/(1024*1024):.1f} MB)")
    report.extracted_evidence["metadata"].append(f"Average sector entropy: {avg_entropy:.2f}")
    if filesystem_types:
        report.extracted_evidence["fs_artifacts"].extend(filesystem_types)
    if found_windows_registry:
        report.extracted_evidence["registry_keys"].append("Windows Registry Hive regf header detected")
    if avg_entropy > 7.2:
        report.extracted_evidence["obfuscation"].append(f"High Average Disk Entropy: {avg_entropy:.2f}/8.0")

    try:
        _scan_file_for_network_iocs(filepath, report)
        import urllib.parse
        domains = [urllib.parse.urlparse(u).netloc for u in report.extracted_evidence.get("urls", []) if u]
        if domains:
            report.extracted_evidence["domains"].extend(domains)
            report.extracted_iocs["domains"] = list(set(report.extracted_iocs.get("domains", []) + domains))[:20]
    except Exception:
        pass

    dfir._analyze_disk_evidence(report)


def analyze_archive_streaming(filepath: str, report: DFIRReport):
    """Memory-efficient Archive streaming (ZIP/tar/7z metadata + selective extraction)."""
    report.evidence_type = "ARCHIVE"
    report.initial_access = "Compressed forensic archive (Large File Mode) — listing contents and scanning metadata"
    filename = os.path.basename(filepath)
    file_size = os.path.getsize(filepath)

    target_files = []
    suspicious_files = []

    try:
        if zipfile.is_zipfile(filepath):
            with zipfile.ZipFile(filepath) as zf:
                info_list = zf.infolist()
                
                for info in info_list:
                    fname = info.filename
                    fname_lower = fname.lower()
                    
                    if any(x in fname_lower for x in ["registry", "system32/config", "ntuser.dat", "sam", "system", "software"]):
                        target_files.append(fname)
                    if fname_lower.endswith((".exe", ".dll", ".ps1", ".bat", ".vbs", ".sh")):
                        suspicious_files.append(fname)
                        
                        if info.file_size < 10 * 1024 * 1024:
                            with zf.open(info) as f_in:
                                head_bytes = f_in.read(20000)
                                for word, label, mitre_id in _MALWARE_STRINGS:
                                    if word in head_bytes:
                                        w_str = word.decode()
                                        if w_str in ("mimikatz", "sekurlsa", "lsass.dump"):
                                            report.extracted_evidence["credentials"].append(f"Archive signature: {label} ({w_str})")
                                        elif w_str in ("vssadmin delete", "bcdedit /set"):
                                            report.extracted_evidence["persistence"].append(f"Archive signature: {label} ({w_str})")
                                        else:
                                            report.extracted_evidence["others"].append(f"Archive signature: {label} ({w_str})")
    except Exception as e:
        logger.warning(f"Archive streaming failed: {e}")

    report.extracted_evidence["metadata"].append(f"ZIP Archive: {filename} ({file_size/(1024*1024):.1f} MB)")
    if target_files:
        report.extracted_evidence["registry_keys"].extend(target_files)
    if suspicious_files:
        report.extracted_evidence["fs_artifacts"].extend(suspicious_files)

    dfir._analyze_zip_evidence(report)


def analyze_file_large(filepath: str, filename: str, ftype: str, report: DFIRReport):
    """Route large file (from disk path) to the correct streaming analyzer."""
    _rlog = logging.getLogger(__name__)
    _rlog.info(f"[STREAM] analyze_file_large() called: filename={filename!r}, ftype={ftype!r}, filepath={filepath!r}")
    logger.info(f"Routing large file {filename} ({ftype}) to streaming pipeline.")
    
    if ftype in ("pcap", "pcapng"):
        _rlog.info(f"[STREAM] ↳ routing to analyze_pcap_streaming()")
        analyze_pcap_streaming(filepath, report)
    elif ftype in ("memory", "raw", "dmp"):
        _rlog.info(f"[STREAM] ↳ routing to analyze_memory_streaming()")
        analyze_memory_streaming(filepath, report)
    elif ftype == "disk":
        _rlog.info(f"[STREAM] ↳ routing to analyze_disk_streaming()")
        analyze_disk_streaming(filepath, report)
    elif ftype == "zip":
        _rlog.info(f"[STREAM] ↳ routing to analyze_archive_streaming()")
        analyze_archive_streaming(filepath, report)
    else:
        _rlog.info(f"[STREAM] ↳ routing to generic IOC scanner (ftype={ftype!r} not specifically handled)")
        # Generic fallback
        report.evidence_type = ftype.upper()
        report.initial_access = f"File {filename} (Large File Mode) — executing streaming carving and IOC extraction"
        _scan_file_for_network_iocs(filepath, report)
        
        # Calculate file entropy in blocks
        try:
            entropies = []
            with open(filepath, "rb") as f:
                while True:
                    block = f.read(64 * 1024)
                    if not block:
                        break
                    entropies.append(_calculate_entropy_block(block))
                    if len(entropies) > 100: # limit to 6.4MB
                        break
            if entropies:
                avg_ent = sum(entropies)/len(entropies)
                report.evidence_summary.append(f"Average Shannon entropy: {avg_ent:.2f}/8.0")
                if avg_ent > 7.0:
                    report.add_finding(
                        category="FILE", severity="MEDIUM",
                        title="High Shannon Entropy Detected",
                        detail=f"Large file averages {avg_ent:.2f} entropy, indicating packed, compressed, or encrypted payload.",
                        mitre=["T1027 – Obfuscated Files"]
                    )
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _calculate_entropy_block(data: bytes) -> float:
    """Calculate Shannon entropy of a single block."""
    if not data:
        return 0.0
    freq = [0]*256
    for b in data:
        freq[b] += 1
    total = len(data)
    entropy = -sum((f/total)*math.log2(f/total) for f in freq if f > 0)
    return entropy


def _scan_file_for_network_iocs(filepath: str, report: DFIRReport):
    """Scan a large file for network IOCs (IPs, URLs) in chunks."""
    ip_pattern  = re.compile(b"\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b")
    url_pattern = re.compile(b"https?://[a-zA-Z0-9_\\-\\.\\/\\?&%=]+")
    
    ips:  set[str] = set()
    urls: set[str] = set()
    
    block_size = 128 * 1024 # 128KB
    block_count = 0
    
    with open(filepath, "rb") as f:
        while True:
            block = f.read(block_size)
            if not block:
                break
            block_count += 1
            
            # IPs
            for match in ip_pattern.finditer(block):
                ip = match.group().decode("latin-1")
                if not any(ip.startswith(p) for p in _PRIV):
                    ips.add(ip)
                    if len(ips) > 50:
                        break
            
            # URLs
            for match in url_pattern.finditer(block):
                url = match.group().decode("latin-1")
                if not any(p in url for p in _PRIV) and "adobe" not in url and "w3.org" not in url:
                    urls.add(url)
                    if len(urls) > 50:
                        break

            # Limit general scanning to first 25MB of a generic file
            if block_count > 200:
                break

    report.extracted_iocs["ips"] = list(set(report.extracted_iocs.get("ips", []) + list(ips)))[:20]
    report.extracted_iocs["urls"] = list(set(report.extracted_iocs.get("urls", []) + list(urls)))[:20]

    if ips or urls:
        report.add_finding(
            category="IOC", severity="MEDIUM",
            title=f"Network IOCs Carved from File ({len(ips)} IPs, {len(urls)} URLs)",
            detail=f"Carved network indicators from block parsing:\nIPs: {', '.join(list(ips)[:5])}\nURLs: {', '.join(list(urls)[:3])}",
            evidence=f"Scanned blocks: {block_count}",
            mitre=["T1041 – Exfiltration over C2"]
        )
