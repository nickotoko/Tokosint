"""Import finished scans into the database and reclaim disk space by deleting their large JSON files.

Once a scan is imported, data/tokosint.db holds its events and the web UI / MCP server read from there, so the big
output.json and validity_false.jsonl can be deleted (everything else - screenshots, logs - is kept). New scans are
imported automatically when they finish; this tool is for scans that were run before, or to reclaim space in bulk.

usage:
  bbot/.venv/bin/python tools/scan_db.py status                 # what is imported and how much disk each scan uses
  bbot/.venv/bin/python tools/scan_db.py import <scan>...        # import named scans (or --all)
  bbot/.venv/bin/python tools/scan_db.py delete <scan>... [--yes]   # import if needed, then delete the JSON files
  bbot/.venv/bin/python tools/scan_db.py delete --all --yes      # reclaim space for every scan
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "web"))
import eventdb
import store

SCANS_DIR = eventdb.SCANS_DIR


def _human(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def _json_bytes(name):
    d = SCANS_DIR / name
    return sum(
        f.stat().st_size
        for f in (d / "output.json", d / "validity_false.jsonl")
        if f.is_file()
    )


def _scan_names():
    return sorted(d.name for d in SCANS_DIR.iterdir() if d.is_dir() and not d.name.startswith(".")
                  and ((d / "output.json").is_file() or eventdb.is_imported(d.name)))  # fmt: skip


def cmd_status():
    imported = eventdb.imported_scans()
    total_on_disk = 0
    rows = []
    for name in _scan_names():
        size = _json_bytes(name)
        total_on_disk += size
        state = "imported" if name in imported else "file only"
        rec = eventdb.import_record(name) if name in imported else None
        if rec and rec["files_deleted"]:
            state = "imported, files deleted"
        rows.append(
            (
                name,
                state,
                _human(size) if size else "—",
                (rec or {}).get("event_count", ""),
            )
        )
    w = max((len(r[0]) for r in rows), default=4)
    print(f"{'scan':<{w}}  {'state':<24}  {'json on disk':>12}  events")
    for name, state, size, events in rows:
        print(f"{name:<{w}}  {state:<24}  {size:>12}  {events}")
    print(
        f"\n{len(rows)} scans, {_human(total_on_disk)} of output.json/validity_false.jsonl on disk"
    )


def cmd_import(names):
    import scans

    for name in names:
        try:
            rec = eventdb.import_scan(name)
            scans.cache_findings(name)  # risk-bearing findings for the Findings view
            nf = len(eventdb.findings_for_scans([name]))
            print(
                f"imported {name}: {rec['event_count']} events, {rec['false_count']} false, {nf} risk findings"
            )
        except store.StoreError as e:
            print(f"skip {name}: {e}")


def cmd_delete(names, yes):
    freed = 0
    to_free = sum(_json_bytes(n) for n in names)
    if not yes:
        print(
            f"would delete output.json/validity_false.jsonl of {len(names)} scans, freeing {_human(to_free)}."
        )
        print("re-run with --yes to proceed.")
        return
    for name in names:
        try:
            eventdb.import_scan(name)
            res = eventdb.delete_files(name)
            freed += res["freed_bytes"]
            print(
                f"deleted {name}: {', '.join(res['deleted']) or '(nothing)'} (+{_human(res['freed_bytes'])})"
            )
        except store.StoreError as e:
            print(f"skip {name}: {e}")
    print(f"\nfreed {_human(freed)}")


def main():
    store.init()
    eventdb.init()
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    cmd, rest = args[0], args[1:]
    yes = "--yes" in rest
    all_scans = "--all" in rest
    names = [a for a in rest if not a.startswith("--")]
    if cmd == "status":
        cmd_status()
    elif cmd in ("import", "delete"):
        targets = _scan_names() if all_scans else names
        if not targets:
            sys.exit(
                f"{cmd}: name a scan (or --all). See tools/scan_db.py with no arguments for usage."
            )
        (cmd_import if cmd == "import" else lambda n: cmd_delete(n, yes))(targets)
    else:
        sys.exit(f"unknown command {cmd!r}: status | import | delete")


if __name__ == "__main__":
    main()
