"""
case_engine.py - Case-Based Forensic Investigation & Correlation Engine

Maintains active cases, ingests artifacts, correlates evidence, deduplicates IOCs,
reconstructs a unified timeline, builds the investigation graph, and compiles
the analyst dashboard.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple
import database as db

logger = logging.getLogger(__name__)

# Default active case output mode per user/chat: chat_id -> mode
_output_modes: Dict[int, str] = {}

def get_chat_mode(chat_id: int) -> str:
    """Get output mode for chat: executive, soc, dfir, hunt, full."""
    return _output_modes.get(chat_id, "executive")

def set_chat_mode(chat_id: int, mode: str):
    """Set default output mode for chat."""
    if mode.lower() in ("executive", "soc", "dfir", "hunt", "full"):
        _output_modes[chat_id] = mode.lower()

def resolve_active_case(chat_id: int) -> str:
    """
    Get the currently active case ID for this chat.
    If none exists, automatically create a new active case.
    """
    case_id = db.get_active_case_id(chat_id)
    if not case_id:
        # Create a new active case
        case_id = f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:4].upper()}"
        db.create_case(case_id, f"Auto-Created Active Case {case_id}")
        db.set_active_case_id(chat_id, case_id)
        logger.info(f"Auto-created active case {case_id} for chat {chat_id}")
    return case_id

def switch_active_case(chat_id: int, case_id: str) -> bool:
    """Switch the active case for this chat. Returns False if case does not exist."""
    case = db.get_case(case_id)
    if not case:
        return False
    db.set_active_case_id(chat_id, case_id)
    return True

def create_new_named_case(chat_id: int, title: str) -> str:
    """Start a new named case and set it as active."""
    case_id = f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:4].upper()}"
    db.create_case(case_id, title)
    db.set_active_case_id(chat_id, case_id)
    return case_id

# ─── Artifact Ingestion ───────────────────────────────────────────────────────

def ingest_artifact(case_id: str, report: Any):
    """
    Ingest a DFIR report object into a case, saving it to database
    and running the deduplication, correlation, and timeline updates.
    """
    # 1. Convert report to dict to serialize
    report_dict = {
        "case_id": report.case_id,
        "evidence_type": report.evidence_type,
        "evidence_name": report.evidence_name,
        "investigator": report.investigator,
        "started_at": report.started_at,
        "completed_at": report.completed_at,
        "verdict": report.verdict,
        "risk_score": report.risk_score,
        "what_happened": report.what_happened,
        "when_happened": report.when_happened,
        "how_happened": report.how_happened,
        "initial_access": report.initial_access,
        "attacker_actions": report.attacker_actions,
        "affected_systems": report.affected_systems,
        "evidence_summary": report.evidence_summary,
        "mitre_techniques": report.mitre_techniques,
        "next_steps": report.next_steps,
        "containment": report.containment,
        "entropy": report.entropy,
        "detected_type": report.detected_type,
        "findings": [
            {
                "timestamp": f.timestamp,
                "category": f.category,
                "severity": f.severity,
                "title": f.title,
                "detail": f.detail,
                "evidence": f.evidence,
                "mitre": f.mitre
            } for f in report.findings
        ],
        "extracted_iocs": report.extracted_iocs,
        "hypothesis": report.hypothesis,
        "attack_chain": report.attack_chain,
        "attack_timeline": report.attack_timeline,
        "extracted_evidence": report.extracted_evidence,
        "network_analytics": report.network_analytics,
        "ti_enrichment": report.ti_enrichment
    }

    # Extract SHA-256 if available
    sha256 = ""
    for entry in report.evidence_summary:
        if "sha-256" in entry.lower():
            parts = entry.split(":")
            if len(parts) > 1:
                sha256 = parts[1].strip()
                break
    if not sha256:
        # Fallback hash
        sha256 = report.case_id

    # Save to case_artifacts
    db.add_case_artifact(
        case_id=case_id,
        filename=report.evidence_name,
        file_type=report.detected_type or report.evidence_type,
        sha256=sha256,
        risk_score=report.risk_score,
        verdict=report.verdict,
        report_json=json.dumps(report_dict)
    )
    logger.info(f"Ingested artifact '{report.evidence_name}' ({report.verdict}) into case {case_id}")

    # Re-run correlation, deduplication, and rebuild case data
    recorrelate_case(case_id)

# ─── Deduplication & Correlation Engine ───────────────────────────────────────

def recorrelate_case(case_id: str):
    """
    Rerun deduplication, cross-evidence correlation, unified timeline,
    and investigation graph reconstruction across all artifacts in the case.
    """
    artifacts = db.get_case_artifacts(case_id)
    if not artifacts:
        return

    # Parse reports
    reports = []
    for art in artifacts:
        try:
            reports.append(json.loads(art["report_json"]))
        except Exception as e:
            logger.error(f"Failed to parse report json for artifact {art['filename']}: {e}")

    if not reports:
        return

    # 1. IOC Deduplication & References tracking
    dedup_iocs: Dict[str, Dict[str, Any]] = {}  # ioc_value -> details
    for rep in reports:
        fname = rep["evidence_name"]
        iocs = rep.get("extracted_iocs") or {}
        for ioc_type in ("ips", "domains", "urls", "emails", "hashes"):
            for ioc_val in iocs.get(ioc_type, []):
                if not ioc_val:
                    continue
                ioc_val_clean = ioc_val.strip()
                if ioc_val_clean not in dedup_iocs:
                    # Calculate baseline confidence
                    # Boost confidence based on TI or artifact detections
                    conf = 50
                    if rep["verdict"] in ("MALICIOUS", "CONFIRMED THREAT"):
                        conf = 75
                    elif rep["verdict"] == "SUSPICIOUS":
                        conf = 60

                    # Check if enriched with high scores
                    ti = rep.get("ti_enrichment") or {}
                    if ioc_val_clean in ti:
                        tdata = ti[ioc_val_clean]
                        if tdata.get("abuse_score", 0) > 20 or tdata.get("risk", 0) > 40:
                            conf = max(conf, 85)

                    dedup_iocs[ioc_val_clean] = {
                        "ioc": ioc_val_clean,
                        "ioc_type": ioc_type[:-1] if ioc_type.endswith("s") else ioc_type,
                        "confidence": conf,
                        "sources": [fname],
                        "first_seen": rep["started_at"],
                        "last_seen": rep["completed_at"] or rep["started_at"]
                    }
                else:
                    # Merge source reference
                    if fname not in dedup_iocs[ioc_val_clean]["sources"]:
                        dedup_iocs[ioc_val_clean]["sources"].append(fname)
                    # Boost confidence due to appearance in multiple artifacts!
                    count = len(dedup_iocs[ioc_val_clean]["sources"])
                    dedup_iocs[ioc_val_clean]["confidence"] = min(98, dedup_iocs[ioc_val_clean]["confidence"] + (count - 1) * 15)
                    # Update timestamps
                    if rep["started_at"] < dedup_iocs[ioc_val_clean]["first_seen"]:
                        dedup_iocs[ioc_val_clean]["first_seen"] = rep["started_at"]
                    if rep["started_at"] > dedup_iocs[ioc_val_clean]["last_seen"]:
                        dedup_iocs[ioc_val_clean]["last_seen"] = rep["started_at"]

    # Save case IOCs
    db.save_case_iocs(case_id, list(dedup_iocs.values()))

    # 2. Evidence Correlation & Investigation Graph Construction
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    # Map to track unique node IDs to prevent duplicates
    registered_nodes = set()

    def add_node(nid: str, label: str, ntype: str, props: Dict[str, Any]):
        if nid not in registered_nodes:
            nodes.append({
                "node_id": nid,
                "node_label": label,
                "node_type": ntype,
                "properties": props
            })
            registered_nodes.add(nid)

    def add_edge(src: str, dst: str, rtype: str, props: Dict[str, Any]):
        # Ensure nodes exist
        if src in registered_nodes and dst in registered_nodes:
            edges.append({
                "source_node": src,
                "target_node": dst,
                "rel_type": rtype,
                "properties": props
            })

    # Add Artifact nodes
    for rep in reports:
        add_node(
            nid=rep["evidence_name"],
            label=rep["evidence_name"],
            ntype="Artifact",
            props={
                "file_type": rep["detected_type"] or rep["evidence_type"],
                "risk_score": rep["risk_score"],
                "verdict": rep["verdict"]
            }
        )

    # Add IOC nodes and connect them to artifacts (APPEARS_IN)
    for ioc_val, info in dedup_iocs.items():
        add_node(
            nid=ioc_val,
            label=ioc_val,
            ntype="IOC",
            props={
                "ioc_type": info["ioc_type"],
                "confidence": info["confidence"]
            }
        )
        for src in info["sources"]:
            add_edge(
                src=ioc_val,
                dst=src,
                rtype="APPEARS_IN",
                props={"confidence": info["confidence"]}
            )

    # Cross-evidence Pivoting & Correlations
    # We will iterate through artifacts to find links and build edges with reasoning
    for i, rep_a in enumerate(reports):
        name_a = rep_a["evidence_name"]
        type_a = rep_a["detected_type"] or rep_a["evidence_type"]

        # Connect threat intel elements if they exists
        ti = rep_a.get("ti_enrichment") or {}
        for ioc_val, ti_data in ti.items():
            if ti_data.get("abuse_score", 0) > 0 or ti_data.get("pulses", 0) > 0 or ti_data.get("risk", 0) > 0:
                intel_node_id = f"TI-{ioc_val}"
                add_node(
                    nid=intel_node_id,
                    label="Threat Intel",
                    ntype="ThreatIntel",
                    props=ti_data
                )
                add_edge(
                    src=ioc_val,
                    dst=intel_node_id,
                    rtype="ENRICHED_BY",
                    props={"confidence": 90}
                )

        # Detect associated malware family / threat actor
        hyp = rep_a.get("hypothesis") or {}
        mal_fam = hyp.get("malware_family")
        if mal_fam and mal_fam != "Unknown" and mal_fam != "None":
            fam_node_id = f"MAL-{mal_fam.replace('/', '_').strip()}"
            add_node(
                nid=fam_node_id,
                label=mal_fam,
                ntype="MalwareFamily",
                props={"attack_type": hyp.get("attack_type", "Unknown")}
            )
            add_edge(
                src=name_a,
                dst=fam_node_id,
                rtype="INFECTED_WITH",
                props={"confidence": hyp.get("confidence", 50)}
            )

        # Connect other artifacts in the case
        for j, rep_b in enumerate(reports):
            if i == j:
                continue
            name_b = rep_b["evidence_name"]
            type_b = rep_b["detected_type"] or rep_b["evidence_type"]

            # Rule A: Same IP appears in Network (PCAP) and Host (Memory/Disk/Office/Script)
            ips_a = set(rep_a.get("extracted_iocs", {}).get("ips", []))
            ips_b = set(rep_b.get("extracted_iocs", {}).get("ips", []))
            common_ips = ips_a & ips_b
            for ip in common_ips:
                add_edge(
                    src=name_a,
                    dst=name_b,
                    rtype="CORRELATED_IP",
                    props={
                        "reason": f"Same IP ({ip}) observed in {type_a} and {type_b}",
                        "confidence": 85,
                        "ip": ip
                    }
                )

            # Rule B: Same Domain/URL appears in Network and Document/Script
            doms_a = set(rep_a.get("extracted_iocs", {}).get("domains", []))
            doms_b = set(rep_b.get("extracted_iocs", {}).get("domains", []))
            common_doms = doms_a & doms_b
            for dom in common_doms:
                add_edge(
                    src=name_a,
                    dst=name_b,
                    rtype="CORRELATED_DOMAIN",
                    props={
                        "reason": f"Same Domain ({dom}) observed in {type_a} and {type_b}",
                        "confidence": 85,
                        "domain": dom
                    }
                )

            # Rule C: Same Hash appears in Executable/PE and memory/disk
            hash_a = set(rep_a.get("extracted_iocs", {}).get("hashes", []))
            hash_b = set(rep_b.get("extracted_iocs", {}).get("hashes", []))
            common_hash = hash_a & hash_b
            for h in common_hash:
                add_edge(
                    src=name_a,
                    dst=name_b,
                    rtype="CORRELATED_HASH",
                    props={
                        "reason": f"Same Hash ({h[:16]}...) observed in {type_a} and {type_b}",
                        "confidence": 95,
                        "hash": h
                    }
                )

            # Rule D: File Name matches between memory dump and disk image
            files_a = set(rep_a.get("extracted_evidence", {}).get("fs_artifacts", []))
            files_b = set(rep_b.get("extracted_evidence", {}).get("fs_artifacts", []))
            # Also check filenames list
            f_list_a = set(rep_a.get("extracted_iocs", {}).get("filenames", []))
            f_list_b = set(rep_b.get("extracted_iocs", {}).get("filenames", []))
            all_files_a = files_a | f_list_a
            all_files_b = files_b | f_list_b
            common_files = all_files_a & all_files_b
            for fname in common_files:
                if fname and len(fname) > 3 and not fname.endswith(".dll"):
                    add_edge(
                        src=name_a,
                        dst=name_b,
                        rtype="CORRELATED_FILENAME",
                        props={
                            "reason": f"Same Filename ({fname}) observed in {type_a} and {type_b}",
                            "confidence": 80,
                            "filename": fname
                        }
                    )

            # Rule E: Persistence mechanisms (registry run keys/scheduled tasks) pointing to file analyzed
            p_a = set(rep_a.get("extracted_evidence", {}).get("persistence", []))
            p_b = set(rep_b.get("extracted_evidence", {}).get("persistence", []))
            # Cross reference with name_b if it is an executable
            if type_b in ("pe", "elf", "exe", "dll"):
                base_name_b = name_b.lower()
                for p_entry in (p_a | p_b):
                    if base_name_b in p_entry.lower():
                        add_edge(
                            src=name_a,
                            dst=name_b,
                            rtype="PERSISTENCE_FOR",
                            props={
                                "reason": f"Persistence mechanism in {type_a} references executable {name_b}",
                                "confidence": 90
                            }
                        )

    # Save case graph nodes and relationships
    db.save_case_graph(case_id, nodes, edges)

    # 3. Unified Timeline Reconstruction
    merged_timeline: List[Dict[str, Any]] = []
    
    # Track events and sort them
    for rep in reports:
        fname = rep["evidence_name"]
        timeline = rep.get("attack_timeline") or []
        for ev in timeline:
            ts = ev.get("time") or "T+0"
            desc = ev.get("event") or ""
            
            # Map severity based on event description keywords
            sev = "INFO"
            desc_lower = desc.lower()
            if any(x in desc_lower for x in ("mimikatz", "beacon", "c2", "ransomware", "credentials", "critical")):
                sev = "CRITICAL"
            elif any(x in desc_lower for x in ("injected", "persistence", "suspicious", "powershell", "macro")):
                sev = "HIGH"
            elif any(x in desc_lower for x in ("download", "http", "port scan")):
                sev = "MEDIUM"
                
            merged_timeline.append({
                "timestamp": ts,
                "event_description": desc,
                "source_artifact": fname,
                "severity": sev
            })

    # Sort helper: Put relative T+0 timings at the top (sorted by order of ingestion),
    # followed by ISO timestamps sorted chronologically.
    def sort_key(x):
        ts = x["timestamp"]
        # If it is like T+0 or similar, prefix with a space so it sorts first
        if "T+" in ts or "Unknown" in ts or "?" in ts:
            return (0, ts)
        try:
            # Try to parse timestamp
            # Handles 'YYYY-MM-DD HH:MM:SS UTC'
            clean_ts = ts.replace(" UTC", "")
            return (1, clean_ts)
        except Exception:
            return (2, ts)

    merged_timeline.sort(key=sort_key)
    
    # Save case timeline
    db.save_case_timeline(case_id, merged_timeline)
    logger.info(f"Re-correlated case {case_id}: {len(dedup_iocs)} IOCs, {len(nodes)} nodes, {len(edges)} edges, {len(merged_timeline)} timeline events.")

# ─── Case Dashboard Generator ─────────────────────────────────────────────────

def get_proportional_recommendation(confidence: int) -> str:
    if confidence < 40:
        return "Collect more evidence. Base confidence is low. Request memory dump, event logs, or PCAP from the target system before initiating containment."
    elif confidence < 60:
        return "Monitor. Evidence is suspicious but not conclusive. Flag endpoints for enhanced logging and run a full antivirus / YARA scan."
    elif confidence < 80:
        return "Investigate immediately. Perform manual analysis of code signing, check execution arguments, and trace associated network destinations."
    elif confidence < 95:
        return "Contain affected host. High-confidence malicious activity detected. Isolate the endpoint from the network and revoke user active sessions."
    else:
        return "Escalate incident. Critical threat confirmed. Trigger the Incident Response plan, preserve forensics, and notify the security operations manager."

def generate_case_dashboard(case_id: str) -> Dict[str, Any]:
    """
    Query database and synthesize the high-level Analyst Dashboard for the case.
    """
    case = db.get_case(case_id)
    if not case:
        return {}

    artifacts = db.get_case_artifacts(case_id)
    iocs = db.get_case_iocs(case_id)
    timeline = db.get_case_timeline(case_id)
    nodes, edges = db.get_case_graph(case_id)
    notes = db.get_analyst_notes(case_id)

    # 1. Overall Risk Score & Severity
    # Base risk is max risk of any artifact, boosted by number of artifacts and correlations
    if not artifacts:
        return {
            "case_id": case_id,
            "title": case["title"],
            "status": case["status"],
            "verdict": "UNKNOWN",
            "risk_score": 0,
            "severity": "INFO",
            "confidence": 0,
            "artifacts_count": 0,
            "iocs_count": 0,
            "critical_finding": "No evidence uploaded yet.",
            "initial_access": "Unknown",
            "malware_family": "None",
            "objective": "Unknown",
            "mitre_summary": [],
            "next_action": "Upload forensic evidence (PCAP, Memory, Executables, PDF, Images).",
            "threat_intel_score": 0,
            "evidence_score": 0,
            "correlation_score": 0,
            "reasoning_score": 0,
            "fp_probability": 0.0,
            "contradictions_count": 0,
            "correlations_count": 0
        }

    max_art_risk = max(art["risk_score"] for art in artifacts)
    # Correlation boost: +5 per cross-artifact relationship
    corr_count = len([e for e in edges if e["rel_type"].startswith("CORRELATED_")])
    risk_score = min(100, max_art_risk + (corr_count * 5))
    
    # 2. Advanced Metrics and Scores calculation (Phase 9)
    from decision_engine import _compute_fp_probability
    
    ti_scores = []
    fp_probs = []
    for art in artifacts:
        try:
            rep = json.loads(art["report_json"])
            ti = rep.get("ti_enrichment") or {}
            for ioc, data in ti.items():
                vt_mal = data.get("vt_malicious", 0) or 0
                vt_total = data.get("vt_total", 0) or 0
                ab_score = data.get("abuse_score", 0) or 0
                otx_pulses = data.get("otx_pulses", 0) or 0
                vt_ratio = (vt_mal / vt_total * 100) if vt_total > 0 else min(vt_mal * 10, 100)
                ti_score = min(max(vt_ratio, ab_score, min(otx_pulses * 20, 100)), 100)
                ti_scores.append(ti_score)
                fp_probs.append(_compute_fp_probability(ioc, data.get("ioc_type", "domain")))
        except Exception:
            pass
    threat_intel_score = int(max(ti_scores)) if ti_scores else 0
    fp_probability = max(fp_probs) if fp_probs else 0.0

    # Evidence Score: Total volume and quality of evidence (0-100)
    total_weight = 0
    contradictions_count = 0
    all_findings = []
    for art in artifacts:
        try:
            rep = json.loads(art["report_json"])
            findings = rep.get("findings", [])
            for f in findings:
                all_findings.append({
                    "title": f["title"],
                    "detail": f["detail"],
                    "severity": f["severity"],
                    "artifact": art["filename"]
                })
                # Check for contradictions in findings
                title_lower = f.get("title", "").lower()
                detail_lower = f.get("detail", "").lower()
                if "contradiction" in title_lower or "contradiction" in detail_lower:
                    contradictions_count += 1
                
                sev = f.get("severity", "INFO")
                if sev == "CRITICAL": total_weight += 30
                elif sev == "HIGH": total_weight += 20
                elif sev == "MEDIUM": total_weight += 10
                elif sev == "LOW": total_weight += 5
                else: total_weight += 1
        except Exception:
            pass
    evidence_score = min(total_weight, 100)

    # Correlation Score: Level of cross-artifact connections (0-100)
    if corr_count >= 3:
        correlation_score = 100
    elif corr_count == 2:
        correlation_score = 70
    elif corr_count == 1:
        correlation_score = 40
    else:
        correlation_score = 0

    # Reasoning Score: Cohesiveness of evidence links, penalized by contradictions (0-100)
    base_reasoning = 85
    if correlation_score > 0:
        base_reasoning += 15
    base_reasoning -= contradictions_count * 20
    reasoning_score = max(0, min(base_reasoning, 100))

    # Overall Confidence (Composite confidence score)
    composite_conf = (evidence_score * 0.4) + (correlation_score * 0.3) + (threat_intel_score * 0.3)
    if contradictions_count > 0:
        composite_conf *= 0.8
    if fp_probability > 0:
        composite_conf *= (1.0 - fp_probability)
    confidence = max(5, min(int(composite_conf), 100))

    # Apply manual verdict override if exists
    case_note = db.get_analyst_note(case_id, "case", case_id)
    verdict = case["manual_verdict"]
    if case_note and case_note.get("manual_verdict") and case_note["manual_verdict"] != "UNKNOWN":
        verdict = case_note["manual_verdict"]
    else:
        # Auto verdict based on contradictions and risk
        if contradictions_count > 0:
            verdict = "MIXED EVIDENCE"
        elif risk_score >= 75:
            verdict = "CONFIRMED THREAT"
        elif risk_score >= 40:
            verdict = "MALICIOUS"
        elif risk_score >= 15:
            verdict = "SUSPICIOUS"
        else:
            verdict = "BENIGN"

    severity = "INFO"
    if risk_score >= 75:
        severity = "CRITICAL"
    elif risk_score >= 50:
        severity = "HIGH"
    elif risk_score >= 25:
        severity = "MEDIUM"
    elif risk_score >= 10:
        severity = "LOW"

    # 3. MITRE ATT&CK Summary
    mitre_set = set()
    for art in artifacts:
        try:
            rep = json.loads(art["report_json"])
            for tech in rep.get("mitre_techniques", []):
                mitre_set.add(tech)
        except Exception:
            pass
    mitre_summary = sorted(list(mitre_set))

    # 4. Synthesize Most Critical Finding
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda x: severity_order.get(x["severity"], 4))
    
    critical_finding = "No critical findings listed."
    if all_findings:
        top_f = all_findings[0]
        critical_finding = f"[{top_f['severity']}] {top_f['title']} (in {top_f['artifact']}) — {top_f['detail'][:180]}..."

    # Apply manual note override for critical finding if bookmarks or note exists
    bookmarked_findings = [n for n in notes if n["target_type"] == "finding" and n.get("bookmark") == 1]
    if bookmarked_findings:
        bookmarked_titles = [bf["target_id"] for bf in bookmarked_findings]
        bm_f = [f for f in all_findings if f["title"] in bookmarked_titles]
        if bm_f:
            critical_finding = f"[BOOKMARKED] {bm_f[0]['title']} (in {bm_f[0]['artifact']}) — {bm_f[0]['detail'][:180]}..."

    # 5. Delivery, Malware Family, Objective
    initial_access = "Unknown (Analysis in progress)"
    malware_family = "None Detected"
    objective = "Unknown (Analysis in progress)"
    
    art_types = [art["file_type"] for art in artifacts]
    
    for art in artifacts:
        try:
            rep = json.loads(art["report_json"])
            fam = rep.get("hypothesis", {}).get("malware_family")
            if fam and fam != "Unknown" and fam != "None":
                malware_family = fam
                break
        except Exception:
            pass

    if "office" in art_types or "pdf" in art_types:
        initial_access = "Spearphishing / Malicious Attachment (T1566.001)"
    elif "pcap" in art_types:
        initial_access = "External Network Exploitation / Scanning"
    elif "memory" in art_types or "disk" in art_types:
        initial_access = "Endpoint Compromise / Active Intrusion"

    # Infer Objective
    timeline_events = " ".join(e["event_description"].lower() for e in timeline)
    finding_texts = " ".join(f["title"].lower() + " " + f["detail"].lower() for f in all_findings)
    combined_texts = timeline_events + " " + finding_texts
    
    if any(x in combined_texts for x in ("exfil", "upload", "ftp", "sent bytes")):
        objective = "Data Exfiltration (T1041)"
    elif any(x in combined_texts for x in ("mimikatz", "sekurlsa", "credentials", "login", "password", "lsass")):
        objective = "Credential Theft (T1003)"
    elif any(x in combined_texts for x in ("beacon", "c2", "cobalt", "meterpreter")):
        objective = "Command and Control / Persistence (T1071)"
    elif any(x in combined_texts for x in ("ransom", "encrypt", ".locky", "wannacry")):
        objective = "Data Encryption for Impact (T1486)"
    else:
        if "pcap" in art_types:
            objective = "C2 / Network Reconnaissance"
        elif "memory" in art_types:
            objective = "Process Injection & Privilege Escalation"
        elif "pe" in art_types:
            objective = "Payload Execution & Host Persistence"

    # 6. Recommended Next Action
    next_action = get_proportional_recommendation(confidence)

    return {
        "case_id": case_id,
        "title": case["title"],
        "status": case["status"],
        "verdict": verdict,
        "risk_score": risk_score,
        "severity": severity,
        "confidence": confidence,
        "artifacts_count": len(artifacts),
        "iocs_count": len(iocs),
        "critical_finding": critical_finding,
        "initial_access": initial_access,
        "malware_family": malware_family,
        "objective": objective,
        "mitre_summary": mitre_summary,
        "next_action": next_action,
        "correlations_count": len(edges),
        "threat_intel_score": threat_intel_score,
        "evidence_score": evidence_score,
        "correlation_score": correlation_score,
        "reasoning_score": reasoning_score,
        "fp_probability": fp_probability,
        "contradictions_count": contradictions_count
    }

# ─── Report Formatting & Output Modes (Analyst Workbench) ───────────────────

def analyze_root_cause(artifacts: List[Dict], timeline: List[Dict], findings: List[Dict]) -> str:
    all_text = " ".join(f.get("title", "").lower() + " " + f.get("detail", "").lower() for f in findings)
    all_text += " " + " ".join(e.get("event_description", "").lower() for e in timeline)
    
    if any(x in all_text for x in ("macro", "attachment", "phishing", "spearphish")):
        return "The incident likely originated from a <b>Spearphishing Email</b> containing a malicious attachment. The user opened the attachment and executed embedded macros, which initiated the compromise chain. (Supported by Office/PDF forensic artifacts)."
    elif any(x in all_text for x in ("web shell", "exploit", "cve", "vulnerability")):
        return "The incident likely started due to the <b>exploitation of a vulnerable public-facing service</b>. The attacker exploited a known vulnerability to gain initial access and run commands. (Supported by network traffic and command logs)."
    elif any(x in all_text for x in ("brute force", "credential stuffing", "login fail")):
        return "The incident likely originated from a successful <b>brute force or credential stuffing attack</b> on an exposed interface. (Supported by authentication and network logs)."
    
    return "Root Cause Unknown"

def assess_impact(artifacts: List[Dict], timeline: List[Dict], findings: List[Dict]) -> Dict[str, Any]:
    all_text = " ".join(f.get("title", "").lower() + " " + f.get("detail", "").lower() for f in findings)
    
    c_impact = "LOW"
    i_impact = "LOW"
    a_impact = "LOW"
    
    if any(x in all_text for x in ("exfil", "credential", "lsass", "mimikatz", "dump", "stolen", "private key")):
        c_impact = "HIGH"
    elif any(x in all_text for x in ("download", "beacon", "outbound")):
        c_impact = "MEDIUM"
        
    if any(x in all_text for x in ("ransom", "encrypt", ".locky", "wannacry", "delete", "destroy", "wipe")):
        i_impact = "HIGH"
        a_impact = "HIGH"
    elif any(x in all_text for x in ("write", "modify", "inject", "registry write")):
        i_impact = "MEDIUM"
        
    systems = set()
    users = set()
    for art in artifacts:
        systems.add(art["filename"])
        try:
            rep = json.loads(art["report_json"])
            for sys in rep.get("affected_systems", []):
                systems.add(sys)
        except Exception:
            pass
            
    # Scan text for potential domain accounts
    import re
    user_matches = re.findall(r'\b[a-zA-Z0-9._-]{3,15}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', all_text)
    for m in user_matches:
        if not any(x in m for x in ("w3.org", "adobe.com", "microsoft", "openxmlformats", "xmlsoap")):
            users.add(m)
            
    business_risk = "LOW"
    if c_impact == "HIGH" or i_impact == "HIGH" or a_impact == "HIGH":
        business_risk = "HIGH"
    elif c_impact == "MEDIUM" or i_impact == "MEDIUM":
        business_risk = "MEDIUM"
        
    return {
        "confidentiality": c_impact,
        "integrity": i_impact,
        "availability": a_impact,
        "affected_systems": list(systems) if systems else ["Forensic Endpoint"],
        "affected_users": list(users) if users else ["Domain Users"],
        "business_risk": business_risk
    }

def check_detection_coverage(artifacts: List[Dict]) -> List[str]:
    coverage = set()
    for art in artifacts:
        try:
            rep = json.loads(art["report_json"])
            findings = rep.get("findings", [])
            for f in findings:
                title = f.get("title", "").lower()
                detail = f.get("detail", "").lower()
                if "yara" in title or "yara" in detail:
                    coverage.add("YARA Signature Detections")
                if "sigma" in title or "sigma" in detail:
                    coverage.add("Sigma Behavior Rules")
                if "virustotal" in title or "virustotal" in detail or "vt " in title:
                    coverage.add("VirusTotal Intelligence")
                if "threatfox" in title or "threatfox" in detail:
                    coverage.add("ThreatFox Feed Matches")
                if "correlation" in title or "correlated" in title:
                    coverage.add("Correlation Rules")
                if f.get("mitre"):
                    coverage.add("MITRE ATT&CK Mapping")
                if "behavior" in title or "behavioral" in title:
                    coverage.add("Behavioral Heuristics")
        except Exception:
            pass
            
    if artifacts:
        coverage.add("Static Signature Matchers")
        coverage.add("File Integrity Analyzers")
        
    return sorted(list(coverage))

def suggest_missing_evidence(artifacts: List[Dict]) -> List[str]:
    types = [a["file_type"].lower() for a in artifacts]
    suggestions = []
    
    if "pcap" not in types:
        suggestions.append("Network Packet Capture (PCAP) to analyze active C2 traffic and data transfer volumes.")
    if "memory" not in types:
        suggestions.append("Endpoint Memory Dump (Volatility format) to identify process injection and volatile credentials.")
    if "disk" not in types:
        suggestions.append("Disk Image / Windows Event Logs (EVTX) to build process creation timelines and check logon sessions.")
    if not any(x in ("office", "pdf") for x in types):
        suggestions.append("Suspicious Email Attachments (MSG/EML) or Office documents to verify initial spearphishing vector.")
    
    # Fallback/Default Suggestions
    suggestions.append("Active Registry Hives (NTUSER.DAT) to analyze individual user persistence mechanisms.")
    suggestions.append("Sysmon or OS Firewall Logs to check for local lateral movement indicators.")
    suggestions.append("Active YARA scans on related endpoints to verify host footprint.")
        
    return suggestions

def build_attack_narrative(artifacts: List[Dict], timeline: List[Dict], findings: List[Dict], edges: List[Dict]) -> Dict[str, Any]:
    stages = {
        "Initial Access": {"status": "Not Observed", "evidence": "No evidence supporting this stage"},
        "Delivery": {"status": "Not Observed", "evidence": "No evidence supporting this stage"},
        "Execution": {"status": "Not Observed", "evidence": "No evidence supporting this stage"},
        "Persistence": {"status": "Not Observed", "evidence": "No evidence supporting this stage"},
        "Defense Evasion": {"status": "Not Observed", "evidence": "No evidence supporting this stage"},
        "Command and Control": {"status": "Not Observed", "evidence": "No evidence supporting this stage"},
        "Action on Objectives": {"status": "Not Observed", "evidence": "No evidence supporting this stage"}
    }
    
    art_types = [a["file_type"].lower() for a in artifacts]
    timeline_desc = " ".join(e.get("event_description", "").lower() for e in timeline)
    findings_desc = " ".join((f.get("title", "") + " " + f.get("detail", "")).lower() for f in findings)
    all_text = timeline_desc + " " + findings_desc
    
    # 1. Initial Access
    if "email" in art_types or "phish" in all_text:
        stages["Initial Access"] = {"status": "Confirmed", "evidence": "Email artifact or phishing finding identified in the case."}
    elif any(t in ("office", "pdf", "docx", "xlsx", "doc", "xls", "pdf") for t in art_types):
        stages["Initial Access"] = {"status": "Likely", "evidence": "Presence of Office/PDF documents suggesting spearphishing entry."}
    elif "initial access" in all_text:
        stages["Initial Access"] = {"status": "Possible", "evidence": "Potential initial access markers found in logs."}
        
    # 2. Delivery
    if "attachment" in all_text or "macro" in all_text or "download" in all_text:
        stages["Delivery"] = {"status": "Confirmed", "evidence": "Malicious attachment download or macro execution confirmed."}
    elif "pdf" in art_types or "office" in art_types:
        stages["Delivery"] = {"status": "Likely", "evidence": "Office/PDF artifact present on disk."}
        
    # 3. Execution
    if "powershell" in all_text or "macro executed" in all_text or "process created" in all_text or "cmd.exe" in all_text:
        stages["Execution"] = {"status": "Confirmed", "evidence": "Process execution or scripting activity confirmed."}
    elif "pe" in art_types or "exe" in art_types or "script" in art_types:
        stages["Execution"] = {"status": "Likely", "evidence": "Executable payload or script analyzed."}
        
    # 4. Persistence
    if "registry run key" in all_text or "scheduled task" in all_text or "persistence created" in all_text or "bootkit" in all_text:
        stages["Persistence"] = {"status": "Confirmed", "evidence": "Persistence mechanism (registry/scheduled task) detected."}
    elif "persistence" in all_text:
        stages["Persistence"] = {"status": "Likely", "evidence": "Potential persistence capability or artifacts observed."}
        
    # 5. Defense Evasion / Obfuscation
    if "steganography" in all_text or "embedded file" in all_text or "hidden photoshop" in all_text or "obfuscation" in all_text:
        stages["Defense Evasion"] = {"status": "Confirmed", "evidence": "Steganography or explicit payload obfuscation detected."}
    elif "entropy" in all_text or "packed" in all_text:
        stages["Defense Evasion"] = {"status": "Likely", "evidence": "High entropy or packed payload detected."}
        
    # 6. Command and Control
    if "beaconing" in all_text or "c2 communication" in all_text or "reverse shell" in all_text:
        stages["Command and Control"] = {"status": "Confirmed", "evidence": "C2 beaconing or reverse shell communication detected."}
    elif "pcap" in art_types or "network" in all_text:
        stages["Command and Control"] = {"status": "Likely", "evidence": "Network traffic to external IP addresses observed."}
        
    # 7. Action on Objectives
    if "mimikatz" in all_text or "lsass" in all_text or "exfiltrat" in all_text or "encrypt" in all_text:
        stages["Action on Objectives"] = {"status": "Confirmed", "evidence": "Credential theft, data exfiltration, or encryption detected."}
    elif "ransom" in all_text or "password" in all_text:
        stages["Action on Objectives"] = {"status": "Likely", "evidence": "Indicators of credential harvesting or ransomware observed."}
        
    return stages

def build_attack_path_graph_text(nodes: List[Dict], edges: List[Dict]) -> str:
    lines = []
    
    correlated_edges = [e for e in edges if e["rel_type"].startswith("CORRELATED_") or e["rel_type"] == "APPEARS_IN"]
    if not correlated_edges:
        lines.append("  [Forensic Evidence] ➔ No active correlations detected yet.")
        return "\n".join(lines)
        
    adj = {}
    for e in edges:
        src = e["source_node"]
        dst = e["target_node"]
        rtype = e["rel_type"]
        if src not in adj: adj[src] = []
        adj[src].append((dst, rtype))
        
    seen_edges = set()
    for src, targets in adj.items():
        src_node = next((n for n in nodes if n["node_id"] == src), None)
        src_type = src_node["node_type"] if src_node else "Unknown"
        
        for dst, rtype in targets:
            edge_key = (src, dst, rtype)
            if edge_key in seen_edges:
                continue
            seen_edges.add(edge_key)
            dst_node = next((n for n in nodes if n["node_id"] == dst), None)
            dst_type = dst_node["node_type"] if dst_node else "Unknown"
            
            lines.append(f"  <b>[{src_type}]</b> <code>{src}</code>")
            lines.append(f"         ↓ <i>({rtype})</i>")
            lines.append(f"  <b>[{dst_type}]</b> <code>{dst}</code>")
            lines.append("")
            
    if len(lines) > 20:
        lines = lines[:20] + ["  <i>... (some paths omitted for brevity)</i>"]
        
    return "\n".join(lines)

# ─── Report Formatting & Output Modes (Analyst Workbench) ───────────────────

def format_analyst_dashboard_html(dash: Dict[str, Any]) -> str:
    """Format the Analyst Dashboard as HTML for Telegram output."""
    sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
    dash_line = "─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─"
    
    verdict_emoji = {
        "CONFIRMED THREAT": "🔴", "MALICIOUS": "🟠", "MIXED EVIDENCE": "🟡",
        "SUSPICIOUS": "🟡", "BENIGN": "🟢", "UNKNOWN": "⚪"
    }.get(dash.get("verdict", "UNKNOWN"), "⚪")

    severity_emoji = {
        "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"
    }.get(dash.get("severity", "INFO"), "⚪")

    conf_bar = "█" * (dash.get("confidence", 0) // 10) + "░" * (10 - dash.get("confidence", 0) // 10)

    mitre_text = ""
    if dash.get("mitre_summary"):
        mitre_text = "\n".join(f"  • <code>{m}</code>" for m in dash["mitre_summary"][:4])
        if len(dash["mitre_summary"]) > 4:
            mitre_text += f"\n  • <i>and {len(dash['mitre_summary'])-4} more...</i>"
    else:
        mitre_text = "  <i>No MITRE techniques mapped.</i>"

    html = (
        f"🕵️‍♂️ <b>ANALYST INVESTIGATION DASHBOARD</b>\n"
        f"<code>{sep}</code>\n"
        f"🔬 <b>Case ID:</b>  <code>{dash['case_id']}</code>\n"
        f"🏷 <b>Title:</b>    <code>{dash['title']}</code>\n"
        f"📊 <b>Status:</b>   <code>{dash['status']}</code>\n"
        f"<code>{sep}</code>\n\n"
        f"{verdict_emoji} <b>VERDICT: {dash['verdict']}</b>\n"
        f"🔥 <b>Risk Score:</b> <code>{dash['risk_score']}/100</code>\n"
        f"{severity_emoji} <b>Severity:</b>   <code>{dash['severity']}</code>\n"
        f"🔮 <b>Confidence:</b> <code>[{conf_bar}] {dash['confidence']}%</code>\n\n"
        f"<b>🧬 Evidence Score:</b> <code>{dash.get('evidence_score', 0)}/100</code>\n"
        f"<b>🧠 Reasoning Score:</b><code>{dash.get('reasoning_score', 0)}/100</code>\n"
        f"<b>📡 Threat Intel:</b>   <code>{dash.get('threat_intel_score', 0)}/100</code>\n"
        f"<b>🔄 Correlation:</b>    <code>{dash.get('correlation_score', 0)}/100</code>\n"
        f"<b>⚠️ FP Probability:</b> <code>{dash.get('fp_probability', 0.0)*100:.0f}%</code>\n\n"
        f"<b>📁 Evidence Artifacts:</b> <code>{dash['artifacts_count']}</code> uploaded\n"
        f"<b>📡 Unique IOCs:</b>      <code>{dash['iocs_count']}</code> extracted\n"
        f"<b>🔗 Correlations:</b>     <code>{dash['correlations_count']}</code> relationships\n"
        f"<code>{dash_line}</code>\n\n"
        f"🚨 <b>MOST CRITICAL FINDING:</b>\n"
        f"<i>{dash['critical_finding']}</i>\n\n"
        f"🚪 <b>Likely Initial Access:</b>\n"
        f"<code>{dash['initial_access']}</code>\n\n"
        f"🦠 <b>Malware Family:</b>\n"
        f"<code>{dash['malware_family']}</code>\n\n"
        f"🎯 <b>Likely Objective:</b>\n"
        f"<code>{dash['objective']}</code>\n\n"
        f"🛡 <b>MITRE ATT&CK Summary:</b>\n"
        f"{mitre_text}\n\n"
        f"👉 <b>RECOMMENDED NEXT ACTION:</b>\n"
        f"<b>{dash['next_action']}</b>"
    )
    return html

def format_case_questions_html(case_id: str, dash: Dict[str, Any]) -> str:
    """Format answers to the 5 Core Investigation Questions as HTML."""
    sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    timeline = db.get_case_timeline(case_id)
    iocs = db.get_case_iocs(case_id)
    notes = db.get_analyst_notes(case_id)

    events_summary = ""
    if timeline:
        events_summary = "\n".join(f"  • {e['event_description'][:100]}" for e in timeline[:3])
    else:
        events_summary = "  • Forensic analysis has not identified actionable sequence of events."

    reasoning = f"Because we detected {dash['artifacts_count']} threat indicators across {dash['artifacts_count']} evidence files. "
    if dash["verdict"] in ("MALICIOUS", "CONFIRMED THREAT"):
        reasoning += f"Risk profiling confirms malicious features scoring {dash['risk_score']}/100. "
    else:
        reasoning += "Evidence points towards anomalous activity but threat remains unconfirmed. "

    evidence_support = ""
    crit_iocs = [i["ioc"] for i in iocs[:3]]
    if crit_iocs:
        evidence_support += f"  • Critical IOCs: <code>{', '.join(crit_iocs)}</code>\n"
    manual_notes = [n["note_text"] for n in notes if n["target_type"] == "finding" and n.get("note_text")]
    if manual_notes:
        evidence_support += f"  • Analyst notes: {', '.join(manual_notes[:2])}\n"
    if dash["mitre_summary"]:
        evidence_support += f"  • ATT&CK Techniques: {len(dash['mitre_summary'])} mapping(s)"
    if not evidence_support:
        evidence_support = "  • Triage contains low severity alerts."

    confidence_explanation = (
        f"Overall confidence is <b>{dash['confidence']}%</b>. This score is computed based on "
        f"supporting evidence in {dash['artifacts_count']} artifacts and {dash['correlations_count']} verified pivots."
    )

    investigate_next = dash["next_action"]

    html = (
        f"❓ <b>CORE INVESTIGATION QUESTIONS</b>\n"
        f"<code>{sep}</code>\n\n"
        f"<b>1. What happened?</b>\n"
        f"{events_summary}\n\n"
        f"<b>2. Why do we believe this?</b>\n"
        f"  <i>{reasoning}</i>\n\n"
        f"<b>3. What evidence supports it?</b>\n"
        f"{evidence_support}\n\n"
        f"<b>4. How confident are we?</b>\n"
        f"  ➜ {confidence_explanation}\n\n"
        f"<b>5. What should the analyst investigate next?</b>\n"
        f"  <b>➜ {investigate_next}</b>"
    )
    return html

def format_case_report(case_id: str, mode: str = "executive") -> List[str]:
    """
    Format the complete multi-artifact case report.
    Supports modes: executive, soc, dfir, hunt, full, technical.
    Returns list of HTML pages to send.
    """
    dash = generate_case_dashboard(case_id)
    if not dash:
        return ["⚠️ Case not found."]

    artifacts = db.get_case_artifacts(case_id)
    iocs = db.get_case_iocs(case_id)
    timeline = db.get_case_timeline(case_id)
    nodes, edges = db.get_case_graph(case_id)
    notes = db.get_analyst_notes(case_id)

    # Compile all findings
    all_findings = []
    for art in artifacts:
        try:
            rep = json.loads(art["report_json"])
            for f in rep.get("findings", []):
                all_findings.append(f)
        except Exception:
            pass

    sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━"
    dash_line = "─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─"
    pages = []

    # ─── Executive Report Format ──────────────────────────────────────────────
    if mode == "executive":
        # Page 1: Executive Brief
        root_cause = analyze_root_cause(artifacts, timeline, all_findings)
        impact = assess_impact(artifacts, timeline, all_findings)
        rec_action = get_proportional_recommendation(dash["confidence"])
        
        p1 = (
            f"👑 <b>EXECUTIVE INCIDENT BRIEF</b>\n"
            f"<code>{sep}</code>\n"
            f"🔬 <b>Case ID:</b>  <code>{dash['case_id']}</code>\n"
            f"🏷 <b>Title:</b>    <code>{dash['title']}</code>\n"
            f"🔥 <b>Risk Score:</b> <code>{dash['risk_score']}/100</code> | <b>Severity:</b> <code>{dash['severity']}</code>\n"
            f"🔮 <b>Estimated Confidence:</b> <code>{dash['confidence']}%</code>\n"
            f"<code>{sep}</code>\n\n"
            f"💬 <b>Incident Summary & Root Cause:</b>\n"
            f"{root_cause}\n\n"
            f"🏢 <b>Business Impact Assessment:</b>\n"
            f"  • Confidentiality: <b>{impact['confidentiality']}</b>\n"
            f"  • Integrity:       <b>{impact['integrity']}</b>\n"
            f"  • Availability:    <b>{impact['availability']}</b>\n"
            f"  • Business Risk:   <b>{impact['business_risk']}</b>\n"
            f"  • Affected Systems:<code>{', '.join(impact['affected_systems'][:3])}</code>\n"
            f"  • Affected Users:  <code>{', '.join(impact['affected_users'][:3])}</code>\n\n"
            f"🛡 <b>Recommended Next Actions:</b>\n"
            f"  ➜ {rec_action}\n"
            f"<code>{sep}</code>"
        )
        pages.append(p1)

        # Page 2: Core Triage Questions
        p2 = format_case_questions_html(case_id, dash)
        pages.append(p2)
        return pages

    # ─── Technical Report Format (SOC, DFIR, Hunt, Full, Technical) ───────────
    # Page 1: Technical Summary & Scenarios
    root_cause = analyze_root_cause(artifacts, timeline, all_findings)
    narrative = build_attack_narrative(artifacts, timeline, all_findings, edges)
    
    narrative_text = ""
    for stage, info in narrative.items():
        status_em = {"Confirmed": "🔴", "Likely": "🟠", "Possible": "🟡", "Not Observed": "⚪"}.get(info["status"], "⚪")
        narrative_text += f"  {status_em} <b>{stage}:</b> <code>{info['status'].upper()}</code>\n  ➜ <i>{info['evidence']}</i>\n\n"

    p1 = (
        f"🕵️‍♂️ <b>TECHNICAL INCIDENT SUMMARY</b>\n"
        f"<code>{sep}</code>\n"
        f"🔬 <b>Case ID:</b>  <code>{dash['case_id']}</code> | <b>Verdict:</b> <code>{dash['verdict']}</code>\n"
        f"🔥 <b>Risk:</b> <code>{dash['risk_score']}/100</code> | 🔮 <b>Confidence:</b> <code>{dash['confidence']}%</code>\n"
        f"<code>{sep}</code>\n\n"
        f"💬 <b>Root Cause Analysis:</b>\n"
        f"{root_cause}\n\n"
        f"📈 <b>Attack Scenario Timeline:</b>\n"
        f"{narrative_text}"
        f"<code>{sep}</code>"
    )
    pages.append(p1)

    # Page 2: Core Forensic Answers
    p2 = format_case_questions_html(case_id, dash)
    pages.append(p2)

    # Page 3: Evidence & Threat Intel Summary
    p3 = (
        f"📦 <b>CASE EVIDENCE LIST ({len(artifacts)} total)</b>\n"
        f"<code>{sep}</code>\n\n"
    )
    for i, art in enumerate(artifacts, 1):
        p3 += (
            f"<b>{i}. {art['filename']}</b>\n"
            f"  • Type: <code>{art['file_type'].upper()}</code> | Risk: <b>{art['risk_score']}/100</b>\n"
            f"  • Verdict: <code>{art['verdict']}</code>\n\n"
        )

    p3 += (
        f"📡 <b>DEDUPLICATED INDICATORS ({len(iocs)} total)</b>\n"
        f"<code>{sep}</code>\n"
    )
    for entry in iocs[:10]:
        note_str = ""
        ioc_note = next((n for n in notes if n["target_type"] == "ioc" and n["target_id"] == entry["ioc"]), None)
        if ioc_note:
            note_str = f" 📝 [Note: {ioc_note['note_text']}]"
            if ioc_note.get("manual_verdict") and ioc_note["manual_verdict"] != "UNKNOWN":
                note_str += f" ({ioc_note['manual_verdict']})"

        p3 += (
            f"  • <code>{entry['ioc']}</code> ({entry['ioc_type'].upper()})\n"
            f"    Confidence: <b>{entry['confidence']}%</b> | Files: {', '.join(entry['sources'])}{note_str}\n"
        )
    if len(iocs) > 10:
        p3 += f"  • <i>and {len(iocs) - 10} more IOCs...</i>\n"
    p3 += f"<code>{sep}</code>"
    pages.append(p3)

    # Page 4: Correlation & Detection Coverage
    path_graph = build_attack_path_graph_text(nodes, edges)
    coverage = check_detection_coverage(artifacts)
    coverage_text = "\n".join(f"  • <code>{c}</code>" for c in coverage) if coverage else "  • <i>None detected</i>"

    p4 = (
        f"🔗 <b>CORRELATION GRAPH & DETECTION COVERAGE</b>\n"
        f"<code>{sep}</code>\n\n"
        f"{path_graph}\n"
        f"🛡 <b>Detection Coverage:</b>\n"
        f"{coverage_text}\n"
        f"<code>{sep}</code>"
    )
    pages.append(p4)

    # Page 5: Timeline & Anomalies
    p5 = (
        f"📅 <b>UNIFIED CASE TIMELINE</b>\n"
        f"<code>{sep}</code>\n\n"
    )
    
    # Simple timestamp anomaly detection
    timeline_anomalies = []
    for i, entry in enumerate(timeline):
        desc_lower = entry["event_description"].lower()
        if "stomping" in desc_lower or "out of order" in desc_lower or "future" in desc_lower:
            timeline_anomalies.append(f"  • <code>[{entry['timestamp']}]</code>: {entry['event_description']}")
            
    if timeline:
        for entry in timeline[:12]:
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}.get(entry["severity"], "⚪")
            p5 += (
                f"  {emoji} <code>[{entry['timestamp']}]</code>\n"
                f"  ➜ {entry['event_description']}\n"
                f"    <i>Source: {entry['source_artifact']}</i>\n\n"
            )
        if len(timeline) > 12:
            p5 += f"  • <i>and {len(timeline) - 12} more events... (Use /timeline command)</i>\n\n"
    else:
        p5 += "<i>No timeline events recorded.</i>\n\n"

    if timeline_anomalies:
        p5 += (
            f"⚠️ <b>TIMELINE ANOMALIES DETECTED:</b>\n"
            + "\n".join(timeline_anomalies[:3]) + "\n"
        )
    p5 += f"<code>{sep}</code>"
    pages.append(p5)

    # Page 6: System Recommendations & Next Steps
    missing_ev = suggest_missing_evidence(artifacts)
    missing_ev_text = "\n".join(f"  • {m}" for m in missing_ev)
    rec_action = get_proportional_recommendation(dash["confidence"])

    p6 = (
        f"🛠 <b>SYSTEM RECOMMENDATIONS & NEXT STEPS</b>\n"
        f"<code>{sep}</code>\n\n"
        f"🛡 <b>Incident Response Verdict Action:</b>\n"
        f"  <b>➜ {rec_action}</b>\n\n"
        f"🔍 <b>Missing Evidence Assistant:</b>\n"
        f"<i>Based on what is currently analyzed, we recommend gathering:</i>\n"
        f"{missing_ev_text}\n"
        f"<code>{sep}</code>"
    )
    pages.append(p6)

    return pages
