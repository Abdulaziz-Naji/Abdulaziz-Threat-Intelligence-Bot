"""
database.py - SQLite persistence layer (SOC-grade edition)

Tables:
  - ioc_history    : every /check query ever made
  - watchlist      : IOCs under active monitoring
  - feed_entries   : deduplicated IOC feed database
  - feed_sources   : health and stats per source
  - feed_alerts    : dedup log for sent alerts
  - feed_stats     : time-series stats per source
  - subscriptions  : per-user IOC type subscriptions
  - alerts         : all alerts sent
"""
import sqlite3
import json
from datetime import datetime, timedelta
from typing import Optional
import config

# ─── Connection helper ────────────────────────────────────────────────────────

def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(config.DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    return c


# ─── Schema bootstrap ─────────────────────────────────────────────────────────

def init_db():
    with _conn() as c:
        c.executescript("""
        -- ── Existing tables ──────────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS ioc_history (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc          TEXT    NOT NULL,
            ioc_type     TEXT    NOT NULL,
            risk_level   TEXT,
            threat_score INTEGER,
            vt_malicious INTEGER,
            abuse_score  INTEGER,
            otx_pulses   INTEGER,
            country      TEXT,
            asn          TEXT,
            raw_json     TEXT,
            queried_at   TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS watchlist (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc              TEXT    NOT NULL UNIQUE,
            ioc_type         TEXT    NOT NULL,
            added_by         INTEGER,
            added_at         TEXT    NOT NULL,
            last_checked     TEXT,
            last_risk_level  TEXT,
            last_vt_mal      INTEGER,
            last_abuse       INTEGER,
            last_otx_pulses  INTEGER,
            active           INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc        TEXT,
            alert_type TEXT,
            message    TEXT,
            sent_at    TEXT    NOT NULL
        );

        -- ── New: Feed entries (deduplicated IOC store) ─────────────────────
        CREATE TABLE IF NOT EXISTS feed_entries (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc             TEXT    NOT NULL,
            ioc_type        TEXT    NOT NULL,
            source          TEXT    NOT NULL,
            threat_category TEXT,
            first_seen      TEXT    NOT NULL,
            last_seen       TEXT    NOT NULL,
            risk_score      INTEGER DEFAULT 0,
            confidence      INTEGER DEFAULT 50,
            tags            TEXT    DEFAULT '[]',
            raw_data        TEXT    DEFAULT '{}',
            notified        INTEGER DEFAULT 0,
            UNIQUE(ioc, source)
        );
        CREATE INDEX IF NOT EXISTS idx_fe_ioc      ON feed_entries(ioc);
        CREATE INDEX IF NOT EXISTS idx_fe_source   ON feed_entries(source);
        CREATE INDEX IF NOT EXISTS idx_fe_risk     ON feed_entries(risk_score DESC);
        CREATE INDEX IF NOT EXISTS idx_fe_ioc_type ON feed_entries(ioc_type);
        CREATE INDEX IF NOT EXISTS idx_fe_first    ON feed_entries(first_seen DESC);

        -- ── New: Feed sources health ────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS feed_sources (
            name             TEXT    PRIMARY KEY,
            display_name     TEXT,
            tier             INTEGER DEFAULT 1,
            last_checked     TEXT,
            last_success     TEXT,
            entries_total    INTEGER DEFAULT 0,
            entries_new_24h  INTEGER DEFAULT 0,
            status           TEXT    DEFAULT 'unknown',
            error_msg        TEXT,
            last_http_status INTEGER,
            raw_fetched_count INTEGER,
            parsed_ioc_count  INTEGER,
            rejected_count    INTEGER DEFAULT 0,
            inserted_db_count INTEGER
        );

        -- ── New: Feed alerts dedup log ──────────────────────────────────────
        CREATE TABLE IF NOT EXISTS feed_alerts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc          TEXT    NOT NULL,
            ioc_type     TEXT,
            source       TEXT,
            alert_reason TEXT,
            risk_score   INTEGER,
            sent_at      TEXT    NOT NULL,
            UNIQUE(ioc, source, alert_reason)
        );
        CREATE INDEX IF NOT EXISTS idx_fa_ioc ON feed_alerts(ioc);

        -- ── New: Feed statistics (time series) ──────────────────────────────
        CREATE TABLE IF NOT EXISTS feed_stats (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            recorded_at TEXT    NOT NULL,
            source      TEXT    NOT NULL,
            new_count   INTEGER DEFAULT 0,
            total_count INTEGER DEFAULT 0
        );

        -- ── New: User subscriptions ─────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS subscriptions (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id   INTEGER NOT NULL,
            sub_type  TEXT    NOT NULL,
            created_at TEXT   NOT NULL,
            active    INTEGER DEFAULT 1,
            UNIQUE(user_id, sub_type)
        );

        -- ── New: IOC Enrichment Cache Layer ──────────────────────────────────
        CREATE TABLE IF NOT EXISTS ioc_enrichment_cache (
            ioc            TEXT    PRIMARY KEY,
            ioc_type       TEXT    NOT NULL,
            risk_score     INTEGER DEFAULT 0,
            verdict        TEXT    DEFAULT 'Low',
            sources        TEXT    DEFAULT '[]',
            abuse_score    INTEGER DEFAULT 0,
            vt_malicious   INTEGER DEFAULT 0,
            otx_pulses     INTEGER DEFAULT 0,
            country        TEXT,
            asn            TEXT,
            tags           TEXT    DEFAULT '[]',
            first_seen     TEXT    NOT NULL,
            last_seen      TEXT    NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_iec_ioc_type ON ioc_enrichment_cache(ioc_type);

        -- ── DFIR Investigation Cases ────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS dfir_cases (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id         TEXT    NOT NULL UNIQUE,
            evidence_type   TEXT    NOT NULL,
            evidence_name   TEXT    NOT NULL,
            verdict         TEXT    DEFAULT 'UNKNOWN',
            risk_score      INTEGER DEFAULT 0,
            findings_count  INTEGER DEFAULT 0,
            mitre_count     INTEGER DEFAULT 0,
            iocs_count      INTEGER DEFAULT 0,
            created_at      TEXT    NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_dfir_verdict ON dfir_cases(verdict);
        CREATE INDEX IF NOT EXISTS idx_dfir_created ON dfir_cases(created_at DESC);

        -- ── Case-based Investigation Engine (Phase 5 & 6) ───────────────────
        CREATE TABLE IF NOT EXISTS cases (
            case_id         TEXT    PRIMARY KEY,
            title           TEXT    NOT NULL,
            status          TEXT    DEFAULT 'ACTIVE',
            manual_verdict  TEXT    DEFAULT 'UNKNOWN',
            created_at      TEXT    NOT NULL,
            updated_at      TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS active_cases (
            chat_id         INTEGER PRIMARY KEY,
            case_id         TEXT,
            FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS case_artifacts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id         TEXT    NOT NULL,
            filename        TEXT    NOT NULL,
            file_type       TEXT    NOT NULL,
            sha256          TEXT    NOT NULL,
            risk_score      INTEGER DEFAULT 0,
            verdict         TEXT    DEFAULT 'UNKNOWN',
            report_json     TEXT    NOT NULL,
            added_at        TEXT    NOT NULL,
            FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_ca_case ON case_artifacts(case_id);

        CREATE TABLE IF NOT EXISTS case_iocs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id         TEXT    NOT NULL,
            ioc             TEXT    NOT NULL,
            ioc_type        TEXT    NOT NULL,
            confidence      INTEGER DEFAULT 50,
            sources_json    TEXT    DEFAULT '[]',
            first_seen      TEXT    NOT NULL,
            last_seen       TEXT    NOT NULL,
            FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE,
            UNIQUE(case_id, ioc)
        );
        CREATE INDEX IF NOT EXISTS idx_ci_case ON case_iocs(case_id);

        CREATE TABLE IF NOT EXISTS case_timeline (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id         TEXT    NOT NULL,
            timestamp       TEXT    NOT NULL,
            event_description TEXT  NOT NULL,
            source_artifact TEXT,
            severity        TEXT    DEFAULT 'INFO',
            order_index     INTEGER DEFAULT 0,
            FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_ct_case ON case_timeline(case_id);

        CREATE TABLE IF NOT EXISTS case_graph_nodes (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id         TEXT    NOT NULL,
            node_id         TEXT    NOT NULL,
            node_label      TEXT    NOT NULL,
            node_type       TEXT    NOT NULL,
            properties_json TEXT    DEFAULT '{}',
            FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE,
            UNIQUE(case_id, node_id)
        );

        CREATE TABLE IF NOT EXISTS case_graph_relationships (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id         TEXT    NOT NULL,
            source_node     TEXT    NOT NULL,
            target_node     TEXT    NOT NULL,
            rel_type        TEXT    NOT NULL,
            properties_json TEXT    DEFAULT '{}',
            FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE,
            UNIQUE(case_id, source_node, target_node, rel_type)
        );

        CREATE TABLE IF NOT EXISTS analyst_notes (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id         TEXT    NOT NULL,
            target_type     TEXT    NOT NULL,  -- 'ioc' | 'finding' | 'case'
            target_id       TEXT    NOT NULL,  -- ioc value or finding title or case_id
            note_text       TEXT,
            severity_override TEXT,
            bookmark        INTEGER DEFAULT 0,
            tags_json       TEXT    DEFAULT '[]',
            manual_verdict  TEXT    DEFAULT 'UNKNOWN',
            updated_at      TEXT    NOT NULL,
            FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE,
            UNIQUE(case_id, target_type, target_id)
        );
        """)
        try:
            c.execute("ALTER TABLE feed_sources ADD COLUMN rejected_count INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass



# ═══════════════════════════════════════════════════════════════════════════════
#  DFIR Cases
# ═══════════════════════════════════════════════════════════════════════════════

def save_dfir_case(
    case_id: str,
    evidence_type: str,
    evidence_name: str,
    verdict: str = "UNKNOWN",
    risk_score: int = 0,
    findings_count: int = 0,
    mitre_count: int = 0,
    iocs_count: int = 0,
):
    """Persist a completed DFIR investigation case."""
    now = datetime.utcnow().isoformat()
    with _conn() as c:
        c.execute("""
            INSERT INTO dfir_cases (
                case_id, evidence_type, evidence_name, verdict,
                risk_score, findings_count, mitre_count, iocs_count, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(case_id) DO UPDATE SET
                verdict=excluded.verdict,
                risk_score=excluded.risk_score,
                findings_count=excluded.findings_count,
                mitre_count=excluded.mitre_count,
                iocs_count=excluded.iocs_count
        """, (case_id, evidence_type, evidence_name, verdict,
               risk_score, findings_count, mitre_count, iocs_count, now))


def get_dfir_cases(limit: int = 10) -> list:
    """Retrieve recent DFIR cases, most recent first."""
    with _conn() as c:
        rows = c.execute("""
            SELECT case_id, evidence_type, evidence_name, verdict,
                   risk_score, findings_count, mitre_count, iocs_count, created_at
            FROM dfir_cases
            ORDER BY created_at DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]


# ═══════════════════════════════════════════════════════════════════════════════
#  IOC Enrichment Cache
# ═══════════════════════════════════════════════════════════════════════════════

def save_ioc_enrichment(
    ioc: str,
    ioc_type: str,
    risk_score: int,
    verdict: str,
    sources: list,
    abuse_score: int = 0,
    vt_malicious: int = 0,
    otx_pulses: int = 0,
    country: str = "",
    asn: str = "",
    tags: list = None,
):
    now = datetime.utcnow().isoformat()
    sources_json = json.dumps(sources)
    tags_json = json.dumps(tags or [])
    with _conn() as c:
        c.execute("""
            INSERT INTO ioc_enrichment_cache (
                ioc, ioc_type, risk_score, verdict, sources, abuse_score,
                vt_malicious, otx_pulses, country, asn, tags, first_seen, last_seen
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ioc) DO UPDATE SET
                risk_score=excluded.risk_score,
                verdict=excluded.verdict,
                sources=excluded.sources,
                abuse_score=excluded.abuse_score,
                vt_malicious=excluded.vt_malicious,
                otx_pulses=excluded.otx_pulses,
                country=excluded.country,
                asn=excluded.asn,
                tags=excluded.tags,
                last_seen=excluded.last_seen
        """, (
            ioc, ioc_type, risk_score, verdict, sources_json, abuse_score,
            vt_malicious, otx_pulses, country, asn, tags_json, now, now
        ))


def get_ioc_enrichment(ioc: str) -> Optional[dict]:
    with _conn() as c:
        row = c.execute("SELECT * FROM ioc_enrichment_cache WHERE ioc=?", (ioc,)).fetchone()
    return dict(row) if row else None


# ═══════════════════════════════════════════════════════════════════════════════
#  IOC History
# ═══════════════════════════════════════════════════════════════════════════════

def save_ioc_result(ioc: str, ioc_type: str, result: dict):
    now = datetime.utcnow().isoformat()
    with _conn() as c:
        c.execute("""
            INSERT INTO ioc_history
              (ioc, ioc_type, risk_level, threat_score, vt_malicious,
               abuse_score, otx_pulses, country, asn, raw_json, queried_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (
            ioc, ioc_type,
            result.get("risk_level"),
            result.get("threat_score"),
            result.get("vt_malicious"),
            result.get("abuse_score"),
            result.get("otx_pulses"),
            result.get("country"),
            result.get("asn"),
            json.dumps(result),
            now,
        ))


def get_ioc_history(limit: int = 20) -> list:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM ioc_history ORDER BY queried_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_ioc_history_for(ioc: str) -> list:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM ioc_history WHERE ioc=? ORDER BY queried_at DESC LIMIT 10", (ioc,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_stats() -> dict:
    with _conn() as c:
        total       = c.execute("SELECT COUNT(*) FROM ioc_history").fetchone()[0]
        ips         = c.execute("SELECT COUNT(*) FROM ioc_history WHERE ioc_type='ip'").fetchone()[0]
        domains     = c.execute("SELECT COUNT(*) FROM ioc_history WHERE ioc_type='domain'").fetchone()[0]
        hashes      = c.execute("SELECT COUNT(*) FROM ioc_history WHERE ioc_type IN ('md5','sha1','sha256')").fetchone()[0]
        urls        = c.execute("SELECT COUNT(*) FROM ioc_history WHERE ioc_type='url'").fetchone()[0]
        high_risk   = c.execute(
            "SELECT COUNT(*) FROM ioc_history WHERE risk_level IN ('High','Critical')"
        ).fetchone()[0]
        top_ioc_row = c.execute(
            "SELECT ioc, COUNT(*) as cnt FROM ioc_history GROUP BY ioc ORDER BY cnt DESC LIMIT 1"
        ).fetchone()
        watchlist_count = c.execute("SELECT COUNT(*) FROM watchlist WHERE active=1").fetchone()[0]
        alerts_count    = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        feed_count      = c.execute("SELECT COUNT(*) FROM feed_entries").fetchone()[0]

    return {
        "total": total, "ips": ips, "domains": domains,
        "hashes": hashes, "urls": urls, "high_risk": high_risk,
        "top_ioc": dict(top_ioc_row) if top_ioc_row else None,
        "watchlist": watchlist_count, "alerts": alerts_count,
        "feed_iocs": feed_count,
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  Watchlist
# ═══════════════════════════════════════════════════════════════════════════════

def add_to_watchlist(ioc: str, ioc_type: str, user_id: int) -> bool:
    try:
        with _conn() as c:
            c.execute("""
                INSERT INTO watchlist (ioc, ioc_type, added_by, added_at, active)
                VALUES (?,?,?,?,1)
            """, (ioc, ioc_type, user_id, datetime.utcnow().isoformat()))
        return True
    except sqlite3.IntegrityError:
        with _conn() as c:
            c.execute("UPDATE watchlist SET active=1 WHERE ioc=?", (ioc,))
        return False


def remove_from_watchlist(ioc: str):
    with _conn() as c:
        c.execute("UPDATE watchlist SET active=0 WHERE ioc=?", (ioc,))


def get_watchlist() -> list:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM watchlist WHERE active=1 ORDER BY added_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def get_watchlist_item(ioc: str) -> Optional[dict]:
    with _conn() as c:
        row = c.execute("SELECT * FROM watchlist WHERE ioc=? AND active=1", (ioc,)).fetchone()
    return dict(row) if row else None


def update_watchlist_state(ioc: str, risk_level: str, vt_mal: int, abuse: int, otx: int):
    with _conn() as c:
        c.execute("""
            UPDATE watchlist
            SET last_checked=?, last_risk_level=?, last_vt_mal=?, last_abuse=?, last_otx_pulses=?
            WHERE ioc=?
        """, (datetime.utcnow().isoformat(), risk_level, vt_mal, abuse, otx, ioc))


# ═══════════════════════════════════════════════════════════════════════════════
#  Feed Entries — Core Dedup Logic
# ═══════════════════════════════════════════════════════════════════════════════

def upsert_feed_entry(
    ioc: str,
    ioc_type: str,
    source: str,
    threat_category: str = "",
    risk_score: int = 0,
    confidence: int = 50,
    tags: list = None,
    raw_data: dict = None,
) -> dict:
    """
    Insert or update a feed entry. Returns a dict describing what happened:
      action: 'new' | 'risk_escalated' | 'category_changed' | 'new_source' | 'updated'
      should_alert: bool
    """
    now = datetime.utcnow().isoformat()
    tags_json = json.dumps(tags or [])
    raw_json  = json.dumps(raw_data or {})

    with _conn() as c:
        existing = c.execute(
            "SELECT * FROM feed_entries WHERE ioc=? AND source=?", (ioc, source)
        ).fetchone()

        if existing is None:
            # Check if IOC exists from any other source
            any_source = c.execute(
                "SELECT COUNT(*) FROM feed_entries WHERE ioc=?", (ioc,)
            ).fetchone()[0]

            c.execute("""
                INSERT INTO feed_entries
                  (ioc, ioc_type, source, threat_category, first_seen, last_seen,
                   risk_score, confidence, tags, raw_data, notified)
                VALUES (?,?,?,?,?,?,?,?,?,?,0)
            """, (ioc, ioc_type, source, threat_category, now, now,
                  risk_score, confidence, tags_json, raw_json))

            # Update source total count
            c.execute("""
                UPDATE feed_sources SET entries_total = entries_total + 1,
                entries_new_24h = entries_new_24h + 1 WHERE name=?
            """, (source,))

            if any_source == 0:
                return {"action": "new", "should_alert": True}
            else:
                return {"action": "new_source", "should_alert": True}

        else:
            ex = dict(existing)
            action = "updated"
            should_alert = False

            if risk_score > (ex["risk_score"] or 0) + 10:
                action = "risk_escalated"
                should_alert = True
            elif threat_category and threat_category != ex.get("threat_category", ""):
                action = "category_changed"
                should_alert = True

            c.execute("""
                UPDATE feed_entries
                SET last_seen=?, risk_score=?, confidence=?, tags=?, raw_data=?,
                    threat_category=?
                WHERE ioc=? AND source=?
            """, (now, max(risk_score, ex["risk_score"] or 0), confidence,
                  tags_json, raw_json, threat_category or ex["threat_category"],
                  ioc, source))

            return {"action": action, "should_alert": should_alert}


def get_feed_entries(
    limit: int = 20,
    ioc_type: str = None,
    source: str = None,
    min_risk: int = 0,
    hours: int = None,
) -> list:
    query = "SELECT * FROM feed_entries WHERE risk_score >= ?"
    params = [min_risk]
    if ioc_type:
        query += " AND ioc_type=?"
        params.append(ioc_type)
    if source:
        query += " AND source=?"
        params.append(source)
    if hours:
        since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
        query += " AND first_seen >= ?"
        params.append(since)
    query += " ORDER BY first_seen DESC LIMIT ?"
    params.append(limit)
    with _conn() as c:
        rows = c.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def get_ioc_all_sources(ioc: str) -> list:
    """Return all sources where an IOC was observed."""
    with _conn() as c:
        rows = c.execute(
            "SELECT source, threat_category, first_seen, last_seen, risk_score, tags "
            "FROM feed_entries WHERE ioc=? ORDER BY first_seen DESC",
            (ioc,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_top_threats(limit: int = 10, hours: int = 24) -> list:
    """Return top high-risk IOCs from the last N hours."""
    since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
    with _conn() as c:
        rows = c.execute("""
            SELECT ioc, ioc_type, MAX(risk_score) as max_risk,
                   GROUP_CONCAT(DISTINCT source) as sources,
                   GROUP_CONCAT(DISTINCT threat_category) as categories,
                   MIN(first_seen) as first_seen
            FROM feed_entries
            WHERE first_seen >= ?
            GROUP BY ioc
            ORDER BY max_risk DESC
            LIMIT ?
        """, (since, limit)).fetchall()
    return [dict(r) for r in rows]


def get_feed_count_by_type(hours: int = 24) -> dict:
    since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
    with _conn() as c:
        rows = c.execute("""
            SELECT ioc_type, COUNT(DISTINCT ioc) as cnt
            FROM feed_entries WHERE first_seen >= ?
            GROUP BY ioc_type
        """, (since,)).fetchall()
    return {r["ioc_type"]: r["cnt"] for r in rows}


def get_top_malware_families(limit: int = 5, hours: int = 24) -> list:
    since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
    with _conn() as c:
        rows = c.execute("""
            SELECT threat_category, COUNT(*) as cnt
            FROM feed_entries
            WHERE first_seen >= ? AND threat_category != '' AND threat_category IS NOT NULL
            GROUP BY threat_category ORDER BY cnt DESC LIMIT ?
        """, (since, limit)).fetchall()
    return [dict(r) for r in rows]


# ═══════════════════════════════════════════════════════════════════════════════
#  Feed Sources
# ═══════════════════════════════════════════════════════════════════════════════

def register_feed_source(name: str, display_name: str, tier: int):
    with _conn() as c:
        c.execute("""
            INSERT OR IGNORE INTO feed_sources (name, display_name, tier, status)
            VALUES (?,?,?,'pending')
        """, (name, display_name, tier))


def update_feed_source_status(
    name: str,
    status: str,
    error_msg: str = None,
    new_entries: int = 0,
    last_http_status: int = None,
    raw_fetched_count: int = None,
    parsed_ioc_count: int = None,
    rejected_count: int = None,
    inserted_db_count: int = None,
):
    now = datetime.utcnow().isoformat()
    with _conn() as c:
        c.execute("""
            UPDATE feed_sources
            SET last_checked=?, status=?, error_msg=?,
                last_success=CASE WHEN ? = 'ok' THEN ? ELSE last_success END,
                last_http_status=COALESCE(?, last_http_status),
                raw_fetched_count=COALESCE(?, raw_fetched_count),
                parsed_ioc_count=COALESCE(?, parsed_ioc_count),
                rejected_count=COALESCE(?, rejected_count),
                inserted_db_count=COALESCE(?, inserted_db_count)
            WHERE name=?
        """, (now, status, error_msg, status, now,
              last_http_status, raw_fetched_count, parsed_ioc_count, rejected_count, inserted_db_count,
              name))

        if new_entries > 0:
            c.execute("""
                INSERT INTO feed_stats (recorded_at, source, new_count)
                VALUES (?, ?, ?)
            """, (now, name, new_entries))


def reset_24h_counters():
    """Reset new_24h counters — call once per day."""
    with _conn() as c:
        c.execute("UPDATE feed_sources SET entries_new_24h=0")


def get_all_feed_sources() -> list:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM feed_sources ORDER BY tier, name"
        ).fetchall()
    return [dict(r) for r in rows]


# ═══════════════════════════════════════════════════════════════════════════════
#  Feed Alerts Dedup and Subscriptions (Removed in refactor)
# ═══════════════════════════════════════════════════════════════════════════════


# ═══════════════════════════════════════════════════════════════════════════════
#  Legacy feed_cache (kept for backward compat)
# ═══════════════════════════════════════════════════════════════════════════════

def is_feed_entry_new(feed_name: str, entry_id: str) -> bool:
    with _conn() as c:
        row = c.execute(
            "SELECT id FROM feed_entries WHERE ioc=? AND source=?",
            (entry_id, feed_name)
        ).fetchone()
    return row is None


def mark_feed_entry_seen(feed_name: str, entry_id: str, data: dict = None):
    upsert_feed_entry(
        ioc=entry_id, ioc_type="unknown",
        source=feed_name, raw_data=data or {}
    )


def save_alert(ioc: str, alert_type: str, message: str):
    with _conn() as c:
        c.execute("""
            INSERT INTO alerts (ioc, alert_type, message, sent_at)
            VALUES (?,?,?,?)
        """, (ioc, alert_type, message, datetime.utcnow().isoformat()))


# ═══════════════════════════════════════════════════════════════════════════════
#  SOC Dashboard Analytics
# ═══════════════════════════════════════════════════════════════════════════════

def get_top_countries(limit: int = 10) -> list:
    """Return top countries from IOC history where country data is available."""
    with _conn() as c:
        rows = c.execute("""
            SELECT country, COUNT(*) as cnt
            FROM ioc_history
            WHERE country IS NOT NULL AND country != '' AND country != 'N/A'
            GROUP BY country ORDER BY cnt DESC LIMIT ?
        """, (limit,)).fetchall()
    return [dict(r) for r in rows]


def get_top_asns(limit: int = 10) -> list:
    """Return top ASNs from IOC history."""
    with _conn() as c:
        rows = c.execute("""
            SELECT asn, COUNT(*) as cnt
            FROM ioc_history
            WHERE asn IS NOT NULL AND asn != '' AND asn != 'N/A'
            GROUP BY asn ORDER BY cnt DESC LIMIT ?
        """, (limit,)).fetchall()
    return [dict(r) for r in rows]


def search_feed_entries_by_ioc(ioc: str) -> list:
    """Search feed_entries by exact IOC value — supports /feedsource <ioc> lookup."""
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM feed_entries WHERE ioc=? ORDER BY risk_score DESC",
            (ioc,)
        ).fetchall()
    return [dict(r) for r in rows]


# ═══════════════════════════════════════════════════════════════════════════════
#  Weekly Report Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def get_weekly_stats() -> dict:
    now = datetime.utcnow()
    week_ago = (now - timedelta(days=7)).isoformat()
    two_weeks_ago = (now - timedelta(days=14)).isoformat()

    with _conn() as c:
        new_this_week = c.execute(
            "SELECT COUNT(DISTINCT ioc) FROM feed_entries WHERE first_seen >= ?",
            (week_ago,)
        ).fetchone()[0]

        new_last_week = c.execute(
            "SELECT COUNT(DISTINCT ioc) FROM feed_entries WHERE first_seen >= ? AND first_seen < ?",
            (two_weeks_ago, week_ago)
        ).fetchone()[0]

        top_sources = c.execute("""
            SELECT source, COUNT(DISTINCT ioc) as cnt
            FROM feed_entries WHERE first_seen >= ?
            GROUP BY source ORDER BY cnt DESC LIMIT 5
        """, (week_ago,)).fetchall()

        top_families = c.execute("""
            SELECT threat_category, COUNT(*) as cnt
            FROM feed_entries
            WHERE first_seen >= ? AND threat_category != '' AND threat_category IS NOT NULL
            GROUP BY threat_category ORDER BY cnt DESC LIMIT 5
        """, (week_ago,)).fetchall()

        high_risk_count = c.execute(
            "SELECT COUNT(DISTINCT ioc) FROM feed_entries WHERE first_seen >= ? AND risk_score >= 75",
            (week_ago,)
        ).fetchone()[0]

        by_type = c.execute("""
            SELECT ioc_type, COUNT(DISTINCT ioc) as cnt
            FROM feed_entries WHERE first_seen >= ?
            GROUP BY ioc_type
        """, (week_ago,)).fetchall()

    return {
        "new_this_week":  new_this_week,
        "new_last_week":  new_last_week,
        "top_sources":    [dict(r) for r in top_sources],
        "top_families":   [dict(r) for r in top_families],
        "high_risk_count": high_risk_count,
        "by_type":        {r["ioc_type"]: r["cnt"] for r in by_type},
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  Case Engine Persistence Helpers (Phase 5 & 6)
# ═══════════════════════════════════════════════════════════════════════════════

def get_active_case_id(chat_id: int) -> Optional[str]:
    """Retrieve the currently active case ID for a chat."""
    with _conn() as c:
        row = c.execute("SELECT case_id FROM active_cases WHERE chat_id=?", (chat_id,)).fetchone()
        return row["case_id"] if row else None


def set_active_case_id(chat_id: int, case_id: str):
    """Set the currently active case ID for a chat."""
    with _conn() as c:
        c.execute("""
            INSERT INTO active_cases (chat_id, case_id)
            VALUES (?, ?)
            ON CONFLICT(chat_id) DO UPDATE SET case_id=excluded.case_id
        """, (chat_id, case_id))


def create_case(case_id: str, title: str, status: str = 'ACTIVE'):
    """Create a new case."""
    now = datetime.utcnow().isoformat()
    with _conn() as c:
        c.execute("""
            INSERT INTO cases (case_id, title, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(case_id) DO UPDATE SET title=excluded.title, status=excluded.status, updated_at=excluded.updated_at
        """, (case_id, title, status, now, now))


def update_case_verdict(case_id: str, verdict: str):
    """Update manual verdict of a case."""
    now = datetime.utcnow().isoformat()
    with _conn() as c:
        c.execute("UPDATE cases SET manual_verdict=?, updated_at=? WHERE case_id=?", (verdict, now, case_id))


def get_case(case_id: str) -> Optional[dict]:
    """Get a single case details."""
    with _conn() as c:
        row = c.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
        return dict(row) if row else None


def get_all_cases() -> list[dict]:
    """Get all cases, sorted by creation date descending."""
    with _conn() as c:
        rows = c.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]


def add_case_artifact(case_id: str, filename: str, file_type: str, sha256: str, risk_score: int, verdict: str, report_json: str):
    """Link an artifact to a case."""
    now = datetime.utcnow().isoformat()
    with _conn() as c:
        c.execute("""
            INSERT INTO case_artifacts (case_id, filename, file_type, sha256, risk_score, verdict, report_json, added_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (case_id, filename, file_type, sha256, risk_score, verdict, report_json, now))


def get_case_artifacts(case_id: str) -> list[dict]:
    """Get all artifacts linked to a case."""
    with _conn() as c:
        rows = c.execute("SELECT * FROM case_artifacts WHERE case_id=? ORDER BY added_at ASC", (case_id,)).fetchall()
        return [dict(r) for r in rows]


def save_case_iocs(case_id: str, iocs: list[dict]):
    """Bulk save/upsert case IOCs."""
    now = datetime.utcnow().isoformat()
    with _conn() as c:
        for ioc in iocs:
            sources_json = json.dumps(ioc.get("sources", []))
            c.execute("""
                INSERT INTO case_iocs (case_id, ioc, ioc_type, confidence, sources_json, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(case_id, ioc) DO UPDATE SET
                    confidence=excluded.confidence,
                    sources_json=excluded.sources_json,
                    last_seen=excluded.last_seen
            """, (case_id, ioc["ioc"], ioc["ioc_type"], ioc.get("confidence", 50), sources_json, ioc.get("first_seen", now), ioc.get("last_seen", now)))


def get_case_iocs(case_id: str) -> list[dict]:
    """Get all IOCs extracted across a case."""
    with _conn() as c:
        rows = c.execute("SELECT * FROM case_iocs WHERE case_id=? ORDER BY confidence DESC", (case_id,)).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["sources"] = json.loads(d["sources_json"])
            except Exception:
                d["sources"] = []
            result.append(d)
        return result


def save_case_timeline(case_id: str, events: list[dict]):
    """Save the unified case timeline (replaces existing case timeline)."""
    with _conn() as c:
        c.execute("DELETE FROM case_timeline WHERE case_id=?", (case_id,))
        for idx, ev in enumerate(events):
            c.execute("""
                INSERT INTO case_timeline (case_id, timestamp, event_description, source_artifact, severity, order_index)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (case_id, ev["timestamp"], ev["event_description"], ev.get("source_artifact"), ev.get("severity", "INFO"), idx))


def get_case_timeline(case_id: str) -> list[dict]:
    """Get unified timeline events for a case."""
    with _conn() as c:
        rows = c.execute("SELECT * FROM case_timeline WHERE case_id=? ORDER BY order_index ASC", (case_id,)).fetchall()
        return [dict(r) for r in rows]


def save_case_graph(case_id: str, nodes: list[dict], edges: list[dict]):
    """Save case graph nodes and relationships (replaces existing)."""
    with _conn() as c:
        c.execute("DELETE FROM case_graph_nodes WHERE case_id=?", (case_id,))
        c.execute("DELETE FROM case_graph_relationships WHERE case_id=?", (case_id,))
        
        for node in nodes:
            c.execute("""
                INSERT OR IGNORE INTO case_graph_nodes (case_id, node_id, node_label, node_type, properties_json)
                VALUES (?, ?, ?, ?, ?)
            """, (case_id, node["node_id"], node["node_label"], node["node_type"], json.dumps(node.get("properties", {}))))
            
        for edge in edges:
            c.execute("""
                INSERT OR IGNORE INTO case_graph_relationships (case_id, source_node, target_node, rel_type, properties_json)
                VALUES (?, ?, ?, ?, ?)
            """, (case_id, edge["source_node"], edge["target_node"], edge["rel_type"], json.dumps(edge.get("properties", {}))))


def get_case_graph(case_id: str) -> tuple[list[dict], list[dict]]:
    """Retrieve case graph nodes and relationships."""
    with _conn() as c:
        node_rows = c.execute("SELECT * FROM case_graph_nodes WHERE case_id=?", (case_id,)).fetchall()
        edge_rows = c.execute("SELECT * FROM case_graph_relationships WHERE case_id=?", (case_id,)).fetchall()
        
        nodes = []
        for nr in node_rows:
            nd = dict(nr)
            try:
                nd["properties"] = json.loads(nd["properties_json"])
            except Exception:
                nd["properties"] = {}
            nodes.append(nd)
            
        edges = []
        for er in edge_rows:
            ed = dict(er)
            try:
                ed["properties"] = json.loads(ed["properties_json"])
            except Exception:
                ed["properties"] = {}
            edges.append(ed)
            
        return nodes, edges


def save_analyst_note(case_id: str, target_type: str, target_id: str, note_text: str = None, severity_override: str = None, bookmark: int = None, tags: list = None, manual_verdict: str = None):
    """Save or update analyst input for an IOC, finding, or case."""
    now = datetime.utcnow().isoformat()
    tags_str = json.dumps(tags) if tags is not None else None
    with _conn() as c:
        # Check if already exists
        existing = c.execute("SELECT * FROM analyst_notes WHERE case_id=? AND target_type=? AND target_id=?", (case_id, target_type, target_id)).fetchone()
        
        if existing:
            # Build dynamic UPDATE statement based on provided args
            updates = ["updated_at=?"]
            params = [now]
            if note_text is not None:
                updates.append("note_text=?")
                params.append(note_text)
            if severity_override is not None:
                updates.append("severity_override=?")
                params.append(severity_override)
            if bookmark is not None:
                updates.append("bookmark=?")
                params.append(bookmark)
            if tags_str is not None:
                updates.append("tags_json=?")
                params.append(tags_str)
            if manual_verdict is not None:
                updates.append("manual_verdict=?")
                params.append(manual_verdict)
                
            params.extend([case_id, target_type, target_id])
            sql = f"UPDATE analyst_notes SET {', '.join(updates)} WHERE case_id=? AND target_type=? AND target_id=?"
            c.execute(sql, tuple(params))
        else:
            # Insert new
            c.execute("""
                INSERT INTO analyst_notes (case_id, target_type, target_id, note_text, severity_override, bookmark, tags_json, manual_verdict, updated_at)
                VALUES (?, ?, ?, ?, ?, COALESCE(?, 0), COALESCE(?, '[]'), COALESCE(?, 'UNKNOWN'), ?)
            """, (case_id, target_type, target_id, note_text, severity_override, bookmark, tags_str, manual_verdict, now))


def get_analyst_notes(case_id: str) -> list[dict]:
    """Get all analyst notes for a case."""
    with _conn() as c:
        rows = c.execute("SELECT * FROM analyst_notes WHERE case_id=?", (case_id,)).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["tags"] = json.loads(d["tags_json"])
            except Exception:
                d["tags"] = []
            result.append(d)
        return result


def get_analyst_note(case_id: str, target_type: str, target_id: str) -> Optional[dict]:
    """Get a specific analyst note details."""
    with _conn() as c:
        row = c.execute("SELECT * FROM analyst_notes WHERE case_id=? AND target_type=? AND target_id=?", (case_id, target_type, target_id)).fetchone()
        if row:
            d = dict(row)
            try:
                d["tags"] = json.loads(d["tags_json"])
            except Exception:
                d["tags"] = []
            return d
        return None
