"""Tokosint state in SQLite (data/tokosint.db): companies, scan schedules, scans linked to companies,
each company's registry of valid findings and the timeline of newly discovered ones, plus settings (Telegram).

Timeline rule: an event is a VALID finding (type + value, as in the Analysis view) that the company's registry has not
seen before. The first ingested scan of a company is its baseline: its findings are recorded as `baseline` events and
never alerted. Ingesting the same scan twice is a no-op.

The file is created with mode 600 and lives outside git (it holds target data and the Telegram bot token).
"""

import json
import os
import sqlite3
import threading
import time
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "data" / "tokosint.db"
_lock = threading.RLock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS companies (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    targets TEXT NOT NULL DEFAULT '[]',
    alerts_enabled INTEGER NOT NULL DEFAULT 1,
    alert_types TEXT NOT NULL DEFAULT '[]',
    telegram_chat_id TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS schedules (
    id INTEGER PRIMARY KEY,
    company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    cron TEXT NOT NULL,
    modules TEXT NOT NULL DEFAULT '[]',
    enabled INTEGER NOT NULL DEFAULT 1,
    next_run REAL,
    last_run REAL,
    last_scan TEXT NOT NULL DEFAULT '',
    pending INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_links (
    scan TEXT PRIMARY KEY,
    company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    schedule_id INTEGER,
    started_at REAL,
    ingested_at REAL,
    baseline INTEGER NOT NULL DEFAULT 0,
    new_count INTEGER NOT NULL DEFAULT 0,
    valid_count INTEGER NOT NULL DEFAULT 0,
    alert TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS assets (
    company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    data TEXT NOT NULL,
    first_seen_at REAL NOT NULL,
    first_scan TEXT NOT NULL,
    last_seen_at REAL NOT NULL,
    last_scan TEXT NOT NULL,
    PRIMARY KEY (company_id, type, data)
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    scan TEXT NOT NULL,
    at REAL NOT NULL,
    kind TEXT NOT NULL,
    type TEXT NOT NULL,
    data TEXT NOT NULL,
    sources TEXT NOT NULL DEFAULT '[]',
    third_party INTEGER NOT NULL DEFAULT 0,
    details TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS events_company_at ON events (company_id, at DESC);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS status_overrides (
    id INTEGER PRIMARY KEY,
    company_id INTEGER REFERENCES companies(id) ON DELETE SET NULL,
    scan TEXT NOT NULL,
    type TEXT NOT NULL,
    data TEXT NOT NULL,
    status TEXT NOT NULL,
    computed_status TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    at REAL NOT NULL,
    snapshot TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS status_overrides_key ON status_overrides (type, data);
"""


class StoreError(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.code = code


def connect():
    DB_PATH.parent.mkdir(exist_ok=True)
    new = not DB_PATH.exists()
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if new:
        os.chmod(DB_PATH, 0o600)
    return conn


def init():
    with _lock, closing(connect()) as c:
        c.executescript(SCHEMA)
        c.commit()


def _row(r, json_fields=()):
    d = dict(r)
    for f in json_fields:
        d[f] = json.loads(d[f] or "[]")
    return d


# ---------- companies ----------

COMPANY_JSON = ("targets", "alert_types")


def list_companies():
    with closing(connect()) as c:
        rows = c.execute(
            """SELECT co.*,
                      (SELECT COUNT(*) FROM assets a WHERE a.company_id = co.id) AS asset_count,
                      (SELECT COUNT(*) FROM scan_links s WHERE s.company_id = co.id) AS scan_count,
                      (SELECT MAX(started_at) FROM scan_links s WHERE s.company_id = co.id) AS last_scan_at
               FROM companies co ORDER BY co.name COLLATE NOCASE"""
        ).fetchall()
    return [_row(r, COMPANY_JSON) for r in rows]


def get_company(company_id):
    with closing(connect()) as c:
        r = c.execute("SELECT * FROM companies WHERE id = ?", (company_id,)).fetchone()
    if r is None:
        raise StoreError("company not found", 404)
    return _row(r, COMPANY_JSON)


def save_company(data, company_id=None, parse_targets=None):
    """Create or update a company. `parse_targets` validates the target list (scans.parse_targets)."""
    name = str(data.get("name") or "").strip()
    if not name or len(name) > 100:
        raise StoreError("company name is required (up to 100 characters)")
    targets = data.get("targets") or []
    targets = parse_targets(targets) if (parse_targets and targets) else []
    alert_types = [str(t) for t in (data.get("alert_types") or []) if str(t).isupper()]
    chat = str(data.get("telegram_chat_id") or "").strip()
    if chat and not chat.lstrip("-@").replace("_", "").isalnum():
        raise StoreError("invalid Telegram chat id")
    fields = (name, str(data.get("description") or "")[:2000], json.dumps(targets), int(bool(data.get("alerts_enabled", True))),
              json.dumps(alert_types), chat)  # fmt: skip
    with _lock, closing(connect()) as c:
        try:
            if company_id is None:
                cur = c.execute(
                    """INSERT INTO companies (name, description, targets, alerts_enabled, alert_types, telegram_chat_id,
                       created_at) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    fields + (time.time(),),
                )
                company_id = cur.lastrowid
            else:
                cur = c.execute(
                    """UPDATE companies SET name = ?, description = ?, targets = ?, alerts_enabled = ?, alert_types = ?,
                       telegram_chat_id = ? WHERE id = ?""",
                    fields + (company_id,),
                )
                if not cur.rowcount:
                    raise StoreError("company not found", 404)
            c.commit()
        except sqlite3.IntegrityError:
            raise StoreError(f"company {name!r} already exists", 409) from None
    return get_company(company_id)


def delete_company(company_id):
    """Deletes the company with its schedules, registry and timeline. Scan files in scans/ are kept."""
    with _lock, closing(connect()) as c:
        cur = c.execute("DELETE FROM companies WHERE id = ?", (company_id,))
        c.commit()
    if not cur.rowcount:
        raise StoreError("company not found", 404)


# ---------- schedules ----------


def list_schedules(company_id=None):
    q = "SELECT s.*, co.name AS company FROM schedules s JOIN companies co ON co.id = s.company_id"
    args = ()
    if company_id is not None:
        q += " WHERE s.company_id = ?"
        args = (company_id,)
    with closing(connect()) as c:
        rows = c.execute(q + " ORDER BY s.id", args).fetchall()
    return [_row(r, ("modules",)) for r in rows]


def save_schedule(data, next_run, schedule_id=None):
    company_id = int(data.get("company_id") or 0)
    get_company(company_id)
    fields = (company_id, str(data["cron"]), json.dumps(list(data.get("modules") or [])), int(bool(data.get("enabled", True))),
              next_run)  # fmt: skip
    with _lock, closing(connect()) as c:
        if schedule_id is None:
            cur = c.execute(
                "INSERT INTO schedules (company_id, cron, modules, enabled, next_run, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                fields + (time.time(),),
            )
            schedule_id = cur.lastrowid
        else:
            cur = c.execute(
                "UPDATE schedules SET company_id = ?, cron = ?, modules = ?, enabled = ?, next_run = ? WHERE id = ?",
                fields + (schedule_id,),
            )
            if not cur.rowcount:
                raise StoreError("schedule not found", 404)
        c.commit()
    return [s for s in list_schedules() if s["id"] == schedule_id][0]


def delete_schedule(schedule_id):
    with _lock, closing(connect()) as c:
        cur = c.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,))
        c.commit()
    if not cur.rowcount:
        raise StoreError("schedule not found", 404)


def update_schedule_run(schedule_id, **fields):
    allowed = {"next_run", "last_run", "last_scan", "pending"}
    sets = {k: v for k, v in fields.items() if k in allowed}
    if not sets:
        return
    with _lock, closing(connect()) as c:
        c.execute(
            f"UPDATE schedules SET {', '.join(f'{k} = ?' for k in sets)} WHERE id = ?",  # noqa: S608 - keys are allowlisted
            (*sets.values(), schedule_id),
        )
        c.commit()


# ---------- scans of a company ----------


def link_scan(scan, company_id, schedule_id=None, started_at=None):
    get_company(company_id)
    with _lock, closing(connect()) as c:
        existing = c.execute("SELECT company_id FROM scan_links WHERE scan = ?", (scan,)).fetchone()
        if existing and existing["company_id"] != company_id:
            raise StoreError(f"scan {scan} already belongs to another company", 409)
        c.execute(
            "INSERT OR IGNORE INTO scan_links (scan, company_id, schedule_id, started_at) VALUES (?, ?, ?, ?)",
            (scan, company_id, schedule_id, started_at or time.time()),
        )
        c.commit()


def unlink_scan(scan, company_id):
    """Detach a scan from its company (the scan files and the findings cache are kept; the scan becomes free)."""
    with _lock, closing(connect()) as c:
        cur = c.execute("DELETE FROM scan_links WHERE scan = ? AND company_id = ?", (scan, company_id))
        c.commit()
    if cur.rowcount == 0:
        raise StoreError(f"scan {scan} is not linked to this company", 404)


def scan_link(scan):
    with closing(connect()) as c:
        r = c.execute("SELECT * FROM scan_links WHERE scan = ?", (scan,)).fetchone()
    return dict(r) if r else None


def scan_companies():
    """{scan name: company name} for all linked scans."""
    with closing(connect()) as c:
        rows = c.execute("SELECT s.scan, co.name FROM scan_links s JOIN companies co ON co.id = s.company_id").fetchall()
    return {r["scan"]: r["name"] for r in rows}


def company_scans(company_id):
    with closing(connect()) as c:
        rows = c.execute(
            "SELECT * FROM scan_links WHERE company_id = ? ORDER BY started_at DESC", (company_id,)
        ).fetchall()
    return [dict(r) for r in rows]


def ingest(scan, findings, started_at):
    """Records a linked scan's VALID findings in its company's registry and timeline.

    findings: aggregated findings of the scan (scans.aggregate_scan). Returns
    {"company_id", "baseline": bool, "new": [findings new to the company], "skipped": bool}."""
    link = scan_link(scan)
    if link is None:
        raise StoreError(f"scan {scan} is not linked to a company", 404)
    company_id = link["company_id"]
    if link["ingested_at"]:
        return {"company_id": company_id, "baseline": bool(link["baseline"]), "new": [], "skipped": True}
    valid = [f for f in findings if f.get("status") == "valid"]
    at = started_at or link["started_at"] or time.time()
    with _lock, closing(connect()) as c:
        baseline = not c.execute(
            "SELECT 1 FROM scan_links WHERE company_id = ? AND ingested_at IS NOT NULL LIMIT 1", (company_id,)
        ).fetchone()
        known = {(r["type"], r["data"]) for r in c.execute("SELECT type, data FROM assets WHERE company_id = ?", (company_id,))}
        kind = "baseline" if baseline else "new"
        new = []
        for f in valid:
            key = (f["type"], f["data"])
            third = int("third-party" in (f.get("tags") or []))
            if key in known:
                c.execute(
                    "UPDATE assets SET last_seen_at = MAX(last_seen_at, ?), last_scan = ? WHERE company_id = ? AND type = ? AND data = ?",
                    (at, scan, company_id, *key),
                )
                continue
            known.add(key)
            new.append(f)
            c.execute(
                """INSERT INTO assets (company_id, type, data, first_seen_at, first_scan, last_seen_at, last_scan)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (company_id, *key, at, scan, at, scan),
            )
            c.execute(
                """INSERT INTO events (company_id, scan, at, kind, type, data, sources, third_party, details)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (company_id, scan, at, kind, *key, json.dumps(f.get("sources") or []), third,
                 json.dumps(f.get("details") or {}, ensure_ascii=False)),  # fmt: skip
            )
        c.execute(
            """UPDATE scan_links SET ingested_at = ?, started_at = ?, baseline = ?, new_count = ?, valid_count = ?
               WHERE scan = ?""",
            (time.time(), at, int(baseline), len(new), len(valid), scan),
        )
        c.commit()
    return {"company_id": company_id, "baseline": baseline, "new": new, "skipped": False}


def reset_registry(company_id):
    """Clears the company's registry and timeline and marks its scans as not ingested (before a rebuild)."""
    with _lock, closing(connect()) as c:
        c.execute("DELETE FROM assets WHERE company_id = ?", (company_id,))
        c.execute("DELETE FROM events WHERE company_id = ?", (company_id,))
        c.execute(
            "UPDATE scan_links SET ingested_at = NULL, baseline = 0, new_count = 0, valid_count = 0 WHERE company_id = ?",
            (company_id,),
        )
        c.commit()


def set_alert_result(scan, text):
    with _lock, closing(connect()) as c:
        c.execute("UPDATE scan_links SET alert = ? WHERE scan = ?", (text[:500], scan))
        c.commit()


def timeline(company_id, kind=None, type_=None, limit=500):
    """Timeline of a company: per-scan entries (newest first) and the latest events."""
    q = "SELECT * FROM events WHERE company_id = ?"
    args = [company_id]
    if kind:
        q += " AND kind = ?"
        args.append(kind)
    if type_:
        q += " AND type = ?"
        args.append(type_)
    q += " ORDER BY at DESC, id DESC LIMIT ?"
    args.append(int(limit))
    with closing(connect()) as c:
        events = [dict(r) for r in c.execute(q, args)]
        type_counts = {
            r["type"]: r["n"]
            for r in c.execute(
                "SELECT type, COUNT(*) AS n FROM events WHERE company_id = ? AND kind = 'new' GROUP BY type", (company_id,)
            )
        }
    for e in events:
        e["sources"] = json.loads(e["sources"])
        e["details"] = json.loads(e["details"])
        e["third_party"] = bool(e["third_party"])
    return {"scans": company_scans(company_id), "events": events, "new_by_type": type_counts}


# ---------- settings ----------


def get_setting(key, default=""):
    with closing(connect()) as c:
        r = c.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return r["value"] if r else default


def set_setting(key, value):
    with _lock, closing(connect()) as c:
        if value in (None, ""):
            c.execute("DELETE FROM settings WHERE key = ?", (key,))
        else:
            c.execute("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))
        c.commit()


# ---------- manual status overrides ----------
# An analyst corrects a finding's status (valid / historical / false). Every change is appended (never updated):
# the log with the computed status, the analyst's note and a snapshot of the evidence is the training data for
# improving validation. The latest change of a finding wins; status "" reverts to the computed status.
# Scope: the company of the scan (all its scans and its timeline) or, for a scan without a company, that scan.

OVERRIDE_STATUSES = ("valid", "historical", "false", "")
MAX_NOTE = 1000


def add_override(scan, type_, data, status, computed_status="", note="", snapshot=None):
    if status not in OVERRIDE_STATUSES:
        raise StoreError(f"status must be one of valid, historical, false (or empty to revert), got {status!r}")
    if not type_ or data is None or not str(data):
        raise StoreError("type and data of the finding are required")
    link = scan_link(scan)
    company_id = link["company_id"] if link else None
    with _lock, closing(connect()) as c:
        cur = c.execute(
            """INSERT INTO status_overrides (company_id, scan, type, data, status, computed_status, note, at, snapshot)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (company_id, scan, type_, str(data), status, computed_status or "", str(note or "")[:MAX_NOTE], time.time(),
             json.dumps(snapshot or {}, ensure_ascii=False)),  # fmt: skip
        )
        c.commit()
        row = c.execute("SELECT * FROM status_overrides WHERE id = ?", (cur.lastrowid,)).fetchone()
    return _override_row(row)


def _override_row(r):
    d = dict(r)
    d["snapshot"] = json.loads(d.get("snapshot") or "{}")
    return d


def overrides_for_scan(scan):
    """{(type, data): latest override} in effect for a scan (reverts dropped)."""
    link = scan_link(scan)
    with closing(connect()) as c:
        if link:
            rows = c.execute("SELECT * FROM status_overrides WHERE company_id = ? ORDER BY id", (link["company_id"],))
        else:
            rows = c.execute("SELECT * FROM status_overrides WHERE company_id IS NULL AND scan = ? ORDER BY id", (scan,))
        latest = {(r["type"], r["data"]): _override_row(r) for r in rows}
    return {k: v for k, v in latest.items() if v["status"]}


def override_log(limit=5000):
    """The whole change log, newest first (for export / analysis)."""
    with closing(connect()) as c:
        rows = c.execute("SELECT * FROM status_overrides ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [_override_row(r) for r in rows]
