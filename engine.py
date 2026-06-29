"""
LeakSearch Engine Module
Importable backend for Telegram bot integration.
Requires: requests, pyyaml
Provides: run_leaksearch (sync) and run_leaksearch_async (async wrapper)
"""

import os
import json
import requests
import urllib3
import logging
import asyncio

urllib3.disable_warnings()
log = logging.getLogger(__name__)

try:
    import yaml
except Exception:
    yaml = None


def load_config(path=r"c:\Users\user\\.continue\\config.yaml"):
    if not os.path.exists(path):
        return {}
    if yaml is None:
        # Minimal fallback: attempt to read simple key: value pairs
        cfg = {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        cfg[k.strip()] = v.strip().strip('"')
        except Exception:
            return {}
        return cfg

    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        log.exception("Failed to load config: %s", e)
        return {}


CFG = load_config()


# ======== CORE: PROXYNOVA SEARCH ========
def find_leaks_proxynova(query, proxy=None, limit=20, timeout=10):
    """Query proxynova-like API and return list of raw lines."""
    url = f"https://api.proxynova.com/comb?query={query}"
    headers = {"User-Agent": "LeakSearch-Bot/1.0"}

    session = requests.Session()
    if not proxy:
        proxy = CFG.get("proxy")
    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})

    try:
        resp = session.get(url, headers=headers, verify=False, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        lines = data.get("lines", [])
        return lines[:max(0, int(limit))]
    except Exception as e:
        log.debug("proxynova query failed: %s", e)
        return []


# ======== CORE: LOCAL DATABASE SEARCH ========
def find_leaks_local_db(database_path, keyword, limit=20):
    if not database_path:
        database_path = CFG.get("local_db")
    if not database_path or not os.path.exists(database_path):
        return []

    results = []
    try:
        with open(database_path, "r", errors="ignore", encoding="utf-8") as f:
            for line in f:
                if keyword.lower() in line.lower():
                    results.append(line.rstrip("\n"))
                    if len(results) >= limit:
                        break
    except Exception as e:
        log.debug("local db read failed: %s", e)
        return []

    return results


# ======== PARSER (SAFE OUTPUT) ========
def parse_results(raw_results):
    parsed = []
    for line in raw_results:
        try:
            # split at first ':' only
            parts = line.split(":", 1)
            if len(parts) >= 2:
                parsed.append({"account": parts[0].strip(), "password": parts[1].strip(), "raw": line})
            else:
                parsed.append({"raw": line})
        except Exception:
            continue
    return parsed


# ======== MAIN ENGINE ========
def run_leaksearch(target: str, source: str = None, limit: int = 20, proxy: str = None, timeout: int = 10):
    """Synchronous, importable function returning structured dict.

    - target: email/username/ip
    - source: "proxynova" or path to local DB or None (uses default from config)
    """
    source = (source or CFG.get("default_source") or "proxynova").lower()
    proxy = proxy or CFG.get("proxy")

    if source == "proxynova":
        raw = find_leaks_proxynova(target, proxy=proxy, limit=limit, timeout=timeout)
        sources = ["proxynova"]
    else:
        db_path = source if os.path.exists(source) else CFG.get("local_db")
        raw = find_leaks_local_db(db_path, target, limit=limit)
        sources = [db_path or "local_db"]

    parsed = parse_results(raw)

    result = {
        "target": target,
        "found": len(parsed) > 0,
        "count": len(parsed),
        "results": parsed,
        "sources": sources,
        "risk_level": "HIGH" if len(parsed) > 3 else "MEDIUM" if len(parsed) > 0 else "LOW",
        "exposure_type": "email/username/hash-metadata"
    }
    return result


# Async wrapper for integration with async handlers
async def run_leaksearch_async(*, target, source=None, limit=20, proxy=None, timeout=10):
    return await asyncio.to_thread(run_leaksearch, target, source, limit, proxy, timeout)


__all__ = ["run_leaksearch", "run_leaksearch_async", "load_config", "CFG"]
