"""Raw scan events in SQLite (data/tokosint.db, via web/store.py): import a finished scan's output.json and
validity_false.jsonl into the database so reads no longer parse the files on every request and the large JSON
files can be deleted.

Once a scan is imported the database is the source of truth for its events: events_of / false_of return the same
dicts read_events would, in the same order, so aggregation, discovery chains and the per-source report are
unchanged (web/scans.py reads through events_for / false_for, which prefer the database and fall back to the file).

delete_files removes the on-disk output.json and validity_false.jsonl only after a verified import; every other
scan file (screenshots, logs, module_stats, quota snapshots) is kept, since the report and the screenshot gallery
still read those from disk.
"""

import json
import time
from contextlib import closing

import store

ROOT = store.ROOT
SCANS_DIR = ROOT / "scans"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_events (
    scan TEXT NOT NULL,
    seq INTEGER NOT NULL,
    event TEXT NOT NULL,
    PRIMARY KEY (scan, seq)
);
CREATE TABLE IF NOT EXISTS scan_false (
    scan TEXT NOT NULL,
    seq INTEGER NOT NULL,
    event TEXT NOT NULL,
    PRIMARY KEY (scan, seq)
);
CREATE TABLE IF NOT EXISTS scan_imports (
    scan TEXT PRIMARY KEY,
    imported_at REAL NOT NULL,
    event_count INTEGER NOT NULL,
    false_count INTEGER NOT NULL,
    started_at REAL,
    targets TEXT NOT NULL DEFAULT '[]',
    files_deleted INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS scan_findings (
    scan TEXT NOT NULL,
    type TEXT NOT NULL,
    data TEXT NOT NULL,
    risk TEXT,
    status TEXT,
    finding TEXT NOT NULL,
    PRIMARY KEY (scan, type, data)
);
CREATE INDEX IF NOT EXISTS scan_findings_scan ON scan_findings (scan);
"""


def init():
    with store._lock, closing(store.connect()) as c:
        c.executescript(SCHEMA)
        c.commit()


def _iter_lines(path):
    """(seq, line) for each non-empty JSON line of a file; seq starts at 0 and counts only kept lines."""
    seq = 0
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue
            yield seq, line
            seq += 1


def _head(first_line):
    """(started_at, targets) from a scan's first SCAN event line, mirroring scans.scan_head."""
    try:
        first = json.loads(first_line or "{}")
    except ValueError:
        return None, []
    if first.get("type") != "SCAN":
        return None, []
    dj = first.get("data_json") or {}
    started = dj.get("started_at")
    target = dj.get("target") or {}
    targets = target.get("seeds") or target.get("target") or []
    return (float(started) if isinstance(started, (int, float)) else None), [
        str(t) for t in targets
    ]


def is_imported(name):
    with closing(store.connect()) as c:
        return (
            c.execute("SELECT 1 FROM scan_imports WHERE scan = ?", (name,)).fetchone()
            is not None
        )


def imported_scans():
    with closing(store.connect()) as c:
        return {r["scan"] for r in c.execute("SELECT scan FROM scan_imports")}


def import_scan(name, *, replace=False):
    """Import scans/<name>/output.json (+ validity_false.jsonl) into the database.

    No-op if already imported unless replace=True. Returns the import record. The scan's output.json must exist
    (the files are not deleted here - call delete_files for that, after you are satisfied with the import)."""
    d = SCANS_DIR / name
    out = d / "output.json"
    false_log = d / "validity_false.jsonl"
    if not out.is_file():
        raise store.StoreError(f"scan {name!r} has no output.json to import", 404)
    with store._lock, closing(store.connect()) as c:
        if (
            not replace
            and c.execute(
                "SELECT 1 FROM scan_imports WHERE scan = ?", (name,)
            ).fetchone()
        ):
            return _import_row(c, name)
        c.execute("DELETE FROM scan_events WHERE scan = ?", (name,))
        c.execute("DELETE FROM scan_false WHERE scan = ?", (name,))
        started, targets, first_line = None, [], None
        rows, n = [], 0
        for seq, line in _iter_lines(out):
            if first_line is None:
                first_line = line
            rows.append((name, seq, line))
            n += 1
            if len(rows) >= 5000:
                c.executemany(
                    "INSERT INTO scan_events (scan, seq, event) VALUES (?, ?, ?)", rows
                )
                rows = []
        if rows:
            c.executemany(
                "INSERT INTO scan_events (scan, seq, event) VALUES (?, ?, ?)", rows
            )
        if first_line is not None:
            started, targets = _head(first_line)
        fn = 0
        if false_log.is_file():
            frows = []
            for seq, line in _iter_lines(false_log):
                frows.append((name, seq, line))
                fn += 1
                if len(frows) >= 5000:
                    c.executemany(
                        "INSERT INTO scan_false (scan, seq, event) VALUES (?, ?, ?)",
                        frows,
                    )
                    frows = []
            if frows:
                c.executemany(
                    "INSERT INTO scan_false (scan, seq, event) VALUES (?, ?, ?)", frows
                )
        c.execute(
            """INSERT INTO scan_imports (scan, imported_at, event_count, false_count, started_at, targets, files_deleted)
               VALUES (?, ?, ?, ?, ?, ?, 0)
               ON CONFLICT(scan) DO UPDATE SET imported_at = excluded.imported_at, event_count = excluded.event_count,
                   false_count = excluded.false_count, started_at = excluded.started_at, targets = excluded.targets,
                   files_deleted = 0""",
            (name, time.time(), n, fn, started, json.dumps(targets)),
        )
        c.commit()
        return _import_row(c, name)


def _import_row(c, name):
    r = c.execute("SELECT * FROM scan_imports WHERE scan = ?", (name,)).fetchone()
    if r is None:
        return None
    d = dict(r)
    d["targets"] = json.loads(d["targets"] or "[]")
    d["files_deleted"] = bool(d["files_deleted"])
    return d


def import_record(name):
    with closing(store.connect()) as c:
        return _import_row(c, name)


def events_of(name):
    """Parsed events of an imported scan, in original order (same shape as scans.read_events)."""
    with closing(store.connect()) as c:
        rows = c.execute(
            "SELECT event FROM scan_events WHERE scan = ? ORDER BY seq", (name,)
        ).fetchall()
    out = []
    for r in rows:
        try:
            out.append(json.loads(r["event"]))
        except ValueError:
            continue
    return out


def false_of(name):
    with closing(store.connect()) as c:
        rows = c.execute(
            "SELECT event FROM scan_false WHERE scan = ? ORDER BY seq", (name,)
        ).fetchall()
    out = []
    for r in rows:
        try:
            out.append(json.loads(r["event"]))
        except ValueError:
            continue
    return out


def event_count(name):
    with closing(store.connect()) as c:
        r = c.execute(
            "SELECT event_count FROM scan_imports WHERE scan = ?", (name,)
        ).fetchone()
    return r["event_count"] if r else None


def delete_files(name):
    """Delete a scan's output.json and validity_false.jsonl, but only after a verified import (the DB holds the
    same number of events). Other scan files are kept. Returns {deleted: [...], freed_bytes}."""
    rec = import_record(name)
    if rec is None:
        raise store.StoreError(
            f"scan {name!r} is not imported; import it before deleting its files", 409
        )
    d = SCANS_DIR / name
    out = d / "output.json"
    if out.is_file():
        on_disk = sum(1 for _ in _iter_lines(out))
        if on_disk != rec["event_count"]:
            raise store.StoreError(
                f"refusing to delete: output.json has {on_disk} events but the import has {rec['event_count']}; "
                "re-import first", 409)  # fmt: skip
    deleted, freed = [], 0
    for f in (out, d / "validity_false.jsonl"):
        if f.is_file():
            freed += f.stat().st_size
            f.unlink()
            deleted.append(f.name)
    with store._lock, closing(store.connect()) as c:
        c.execute("UPDATE scan_imports SET files_deleted = 1 WHERE scan = ?", (name,))
        c.commit()
    return {"scan": name, "deleted": deleted, "freed_bytes": freed}


def forget(name):
    """Drop a scan's imported events from the database (e.g. after the scan folder was removed)."""
    with store._lock, closing(store.connect()) as c:
        for t in ("scan_events", "scan_false", "scan_imports", "scan_findings"):
            c.execute(f"DELETE FROM {t} WHERE scan = ?", (name,))
        c.commit()


# ---------- cached aggregated findings (for the cross-company Findings view) ----------
# scans.cache_findings computes the risk-bearing findings of a scan and stores them here; the Findings tab unions
# them across a company's scans without re-aggregating the (possibly huge) events on every request.


def store_findings(name, findings):
    """Replace the cached findings of a scan. `findings` is a list of aggregated, risk-annotated finding dicts
    (store the ones that carry a risk level); each is kept whole as JSON plus indexed type/data/risk/status."""
    rows = [
        (
            name,
            f["type"],
            str(f["data"]),
            f.get("risk"),
            f.get("status"),
            json.dumps(f, ensure_ascii=False),
        )
        for f in findings
    ]
    with store._lock, closing(store.connect()) as c:
        c.execute("DELETE FROM scan_findings WHERE scan = ?", (name,))
        if rows:
            c.executemany(
                "INSERT OR REPLACE INTO scan_findings (scan, type, data, risk, status, finding) VALUES (?, ?, ?, ?, ?, ?)",
                rows,
            )
        c.commit()


def has_findings(name):
    with closing(store.connect()) as c:
        return (
            c.execute(
                "SELECT 1 FROM scan_findings WHERE scan = ? LIMIT 1", (name,)
            ).fetchone()
            is not None
        )


def findings_for_scans(scan_names):
    """[(scan, finding dict)] for the cached findings of the given scans."""
    names = list(scan_names)
    if not names:
        return []
    out = []
    with closing(store.connect()) as c:
        qmarks = ",".join("?" * len(names))
        rows = c.execute(
            f"SELECT scan, finding FROM scan_findings WHERE scan IN ({qmarks})",
            names,
        ).fetchall()
    for r in rows:
        try:
            out.append((r["scan"], json.loads(r["finding"])))
        except ValueError:
            continue
    return out
