"""Scans in scans/: list, findings, per-source report and starting new scans through bin/osint.

Standard library only. Scan data stays in scans/ (gitignored).
"""

import contextlib
import ipaddress
import json
import os
import re
import signal
import subprocess
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path

from validity import compute_status

WEB_DIR = Path(__file__).resolve().parent
ROOT = WEB_DIR.parent
SCANS_DIR = ROOT / "scans"
OSINT = ROOT / "bin" / "osint"

MAX_TARGETS = 20
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,59}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
STATUS_RANK = {None: -1, "false": 0, "historical": 1, "valid": 2}


# ---------- reading a scan ----------

def safe_scan_dir(name):
    """Scan directory inside scans/; protects against path traversal."""
    if not name or "/" in name or "\\" in name or name.startswith("."):
        return None
    d = SCANS_DIR / name
    try:
        d.resolve().relative_to(SCANS_DIR.resolve())
    except ValueError:
        return None
    return d


def scan_started_at(path):
    """Start time (unix) of a scan from the SCAN event in its output.json, or None."""
    try:
        with open(path, encoding="utf-8") as fh:
            first = json.loads(fh.readline() or "{}")
    except (OSError, ValueError):
        return None
    started = (first.get("data_json") or {}).get("started_at") if first.get("type") == "SCAN" else None
    return float(started) if isinstance(started, (int, float)) else None


def safe_scan_path(name):
    d = safe_scan_dir(name)
    if d is None:
        return None
    out = d / "output.json"
    return out if out.is_file() else None


def read_events(path):
    events = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except ValueError:
                continue
    return events


def asset_data(e):
    """String form of an event's finding (for dicts - host/url/name/...)."""
    d = e.get("data")
    if d is None:
        d = e.get("data_json")
    if d is None:
        return None
    if isinstance(d, str):
        return d
    # always a string: ASN data is a number, while the UI sorts and searches strings
    v = d.get("host") or d.get("url") or d.get("name") or d.get("asn") or d.get("ip") or d.get("description")
    return str(v) if v is not None else json.dumps(d, ensure_ascii=False)


def source_name(module):
    """DNS records (A, NS, MX...) come from dummy modules - this is dnsresolve's live resolution."""
    if module and module != "SEED" and module.isupper():
        return "dnsresolve"
    return module


DETAIL_FIELDS = ("description", "severity", "confidence", "url", "host", "path", "name", "platform", "profile_name",
                 "technology", "asn", "country", "city", "subnet")  # fmt: skip
MAX_CONTEXTS = 12


def event_details(e):
    """Fields of a dict event that explain the finding (for FINDING - description/severity), as strings."""
    d = e.get("data_json")
    if not isinstance(d, dict):
        d = e.get("data") if isinstance(e.get("data"), dict) else None
    if not d:
        return {}
    return {k: str(d[k])[:500] for k in DETAIL_FIELDS if d.get(k) not in (None, "")}


def read_false(path):
    """The scan's false findings log (validity_false.jsonl next to output.json)."""
    log = Path(path).parent / "validity_false.jsonl"
    return read_events(log) if log.is_file() else []


def aggregate_scan(path, with_false=True):
    """Scan JSONL -> list of findings [{type, data, sources, tags, seen, status, details, contexts, false_reasons}].

    status - valid / historical / false across all discovery paths (web/validity.py), None - an untagged scan.
    with_false - add false findings from validity_false.jsonl (they are not in the scan output): status false
    unless another path confirmed the finding, with the reason in false_reasons."""
    events = read_events(path)
    status = compute_status(events)
    by_key = {}

    def asset(etype, data):
        key = f"{etype}\x00{data}"
        a = by_key.get(key)
        if a is None:
            a = {"type": etype, "data": data, "sources": set(), "tags": set(), "seen": None, "status": None,
                 "details": {}, "contexts": {}, "false_reasons": []}  # fmt: skip
            by_key[key] = a
        return a

    for e in events:
        etype = e.get("type")
        if not etype or etype == "SCAN":
            continue
        data = asset_data(e)
        if data is None:
            continue
        a = asset(etype, data)
        st = status.get(e.get("id"))
        if STATUS_RANK[st] > STATUS_RANK[a["status"]]:
            a["status"] = st
        module = e.get("module")
        if module and module != "SEED":
            a["sources"].add(module)
        for t in e.get("tags", []) or []:
            a["tags"].add(t)
        for k, v in event_details(e).items():
            a["details"].setdefault(k, v)
        ctx = e.get("discovery_context")
        if ctx and len(a["contexts"]) < MAX_CONTEXTS:
            a["contexts"].setdefault(f"{module}\x00{ctx}", {"module": module, "context": ctx[:500]})
        ts = e.get("timestamp")
        if isinstance(ts, (int, float)) and (a["seen"] is None or ts > a["seen"]):
            a["seen"] = ts

    if with_false:
        for r in read_false(path):
            if not r.get("type") or r.get("data") is None:
                continue
            a = asset(r["type"], str(r["data"]))
            if a["status"] is None:
                a["status"] = "false"
            module = r.get("module")
            if module:
                a["sources"].add(module)
            reason = r.get("reason") or "descendant of a false finding"
            entry = {"module": module, "reason": reason, "hidden": bool(r.get("hidden"))}
            if entry not in a["false_reasons"] and len(a["false_reasons"]) < MAX_CONTEXTS:
                a["false_reasons"].append(entry)

    out = []
    for a in by_key.values():
        tags = a["tags"]
        if "in-scope" in tags:
            # a name that entered scope later (a domain promoted by related_domains) is not a third party
            tags.discard("third-party")
        out.append({
            "type": a["type"],
            "data": a["data"],
            "sources": sorted(a["sources"]),
            "tags": sorted(tags),
            "seen": a["seen"],
            "status": a["status"],
            "details": a["details"],
            "contexts": list(a["contexts"].values()),
            "false_reasons": a["false_reasons"],
        })
    out.sort(key=lambda a: (-len(a["sources"]), a["type"], a["data"]))
    return out


# ---------- per-source report ----------

def _console_log(name):
    p = SCANS_DIR / f"{name}.console.log"
    return p if p.is_file() else None


def parse_console(path):
    """From the BBoT console log: loaded modules, setup soft-fails, runtime error states."""
    loaded, failed, errored = [], {}, {}
    if path is None:
        return loaded, failed, errored
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = ANSI_RE.sub("", raw).strip()
            m = re.search(r"Loaded \d+/\d+ scan modules \(([^)]*)\)", line)
            if m:
                loaded = [x for x in m.group(1).split(",") if x]
                continue
            m = re.search(r"Setup (?:soft|hard)-failed for ([a-z0-9_]+): (.*)", line)
            if m:
                failed[m.group(1)] = m.group(2)[:200]
                continue
            m = re.search(r"\] ([a-z0-9_]+): Setting error state: (.*)", line)
            if m:
                errored[m.group(1)] = m.group(2)[:200]
    return loaded, failed, errored


def scan_report(name, producers=None):
    """What and how much each source of the scan found.

    producers - modules that emit data at all: loaded modules outside this set
    (report modules such as affiliates) are left out of the report when they found nothing."""
    d = safe_scan_dir(name)
    path = d / "output.json" if d else None
    if path is None or not path.is_file():
        return None
    events = read_events(path)
    status = compute_status(events)

    scan_info = {}
    per = defaultdict(lambda: {"events": 0, "assets": set(), "types": Counter(), "status": Counter()})
    asset_sources = defaultdict(set)
    for e in events:
        etype = e.get("type")
        if etype == "SCAN":
            dj = e.get("data_json") or {}
            if dj.get("status") or not scan_info:
                scan_info = dj
            continue
        data = asset_data(e)
        module = source_name(e.get("module"))
        if not etype or data is None or not module or module == "SEED":
            continue
        key = (etype, data)
        asset_sources[key].add(module)
        p = per[module]
        p["events"] += 1
        if key not in p["assets"]:
            p["assets"].add(key)
            p["types"][etype] += 1
            p["status"][status.get(e.get("id")) or "none"] += 1

    false_by_module = Counter()
    false_log = d / "validity_false.jsonl"
    if false_log.is_file():
        for r in read_events(false_log):
            false_by_module[source_name(r.get("module"))] += 1

    loaded, failed, errored = parse_console(_console_log(name))
    names = set(per) | set(loaded) | set(failed) | set(errored) | set(false_by_module)
    sources = []
    for m in names:
        p = per.get(m)
        if p is None and producers is not None and m not in producers and m not in failed and m not in errored:
            continue
        assets = len(p["assets"]) if p else 0
        only = sum(1 for k in p["assets"] if len(asset_sources[k]) == 1) if p else 0
        if m in failed:
            state, detail = "failed", failed[m]
        elif m in errored:
            state, detail = "error", errored[m]
        elif assets:
            state, detail = "ok", ""
        else:
            state, detail = "nodata", ""
        sources.append({
            "name": m,
            "state": state,
            "detail": detail,
            "events": p["events"] if p else 0,
            "assets": assets,
            "only": only,
            "types": dict(p["types"].most_common()) if p else {},
            "status": dict(p["status"]) if p else {},
            "false": false_by_module.get(m, 0),
        })
    sources.sort(key=lambda s: (-s["assets"], s["name"]))

    target = scan_info.get("target") or {}
    total_status = Counter()
    by_type = Counter()
    dns_check = Counter()
    third_party = 0
    assets = aggregate_scan(path, with_false=False)
    for a in assets:
        total_status[a["status"] or "none"] += 1
        by_type[a["type"]] += 1
        if "third-party" in a["tags"]:
            third_party += 1
        check = next((t[len("dns-check-"):] for t in a["tags"] if t.startswith("dns-check-")), None)
        if check:
            dns_check[check] += 1
    return {
        "name": name,
        "targets": target.get("seeds") or target.get("target") or [],
        "status": scan_info.get("status"),
        "started_at": scan_info.get("started_at"),
        "finished_at": scan_info.get("finished_at"),
        "duration": scan_info.get("duration"),
        "assets": len(assets),
        "events": sum(1 for e in events if e.get("type") != "SCAN"),
        "by_type": dict(by_type.most_common()),
        "by_status": dict(total_status),
        "dns_check": dict(dns_check),
        "third_party": third_party,
        "false": sum(false_by_module.values()),
        "has_console": _console_log(name) is not None,
        "sources": sources,
    }


# ---------- starting scans ----------

class ScanError(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.code = code


_jobs = {}  # scan name -> {"proc", "targets", "started", "log"}
_lock = threading.Lock()


def parse_targets(raw):
    """Domains and IPs/CIDRs; anything else is rejected (only validated values reach the command line)."""
    items = raw if isinstance(raw, list) else re.split(r"[\s,;]+", str(raw or ""))
    out = []
    for t in items:
        t = str(t).strip().lower().rstrip(".")
        if not t:
            continue
        try:
            out.append(str(ipaddress.ip_network(t, strict=False)) if "/" in t else str(ipaddress.ip_address(t)))
            continue
        except ValueError:
            pass
        t = t.removeprefix("*.")
        if not DOMAIN_RE.match(t):
            raise ScanError(f"not a domain or IP: {t[:80]}")
        out.append(t)
    out = list(dict.fromkeys(out))
    if not out:
        raise ScanError("no targets given")
    if len(out) > MAX_TARGETS:
        raise ScanError(f"at most {MAX_TARGETS} targets per scan")
    return out


def _child_env():
    """Scan environment without the server's BBoT service variables: the server imports BBoT itself
    (module metadata), and with inherited `_BBOT_LOGGING_SETUP` / `_BBOT_MAIN_PID` the scan thinks it is a
    subprocess and writes no INFO log (the report relies on it: loaded modules, setup errors)."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("_BBOT")}
    env["NO_COLOR"] = "1"
    return env


def _restore_sigint():
    # if the server runs in the background (`bin/web &`), SIGINT is inherited as ignored and stopping would fail
    signal.signal(signal.SIGINT, signal.SIG_DFL)


def default_name(targets):
    base = re.sub(r"[^a-z0-9]+", "_", targets[0]).strip("_")[:30] or "scan"
    return f"{base}_{time.strftime('%Y%m%d_%H%M')}"


def running_job():
    with _lock:
        for name, j in _jobs.items():
            if j["proc"].poll() is None:
                return name
    return None


def start_scan(payload, known_sources, on_finish=None, meta=None):
    """payload: {targets, name?, modules?: [...]} - empty modules = the whole passive set.

    on_finish(name, returncode) is called from a watcher thread when the BBoT process exits;
    meta (e.g. company/schedule ids) is kept with the job and shown in job_info."""
    targets = parse_targets(payload.get("targets"))
    name = str(payload.get("name") or "").strip().lower() or default_name(targets)
    if not NAME_RE.match(name):
        raise ScanError("scan name: lowercase latin letters, digits, _ and -, up to 60 characters")
    modules = payload.get("modules") or []
    if not isinstance(modules, list) or any(m not in known_sources for m in modules):
        raise ScanError("unknown source in the module list")

    busy = running_job()
    if busy:
        raise ScanError(f"scan {busy} is already running: wait for it or stop it", 409)
    if (SCANS_DIR / name).exists() or name in _jobs:
        raise ScanError(f"scan {name} already exists, choose another name", 409)

    cmd = [str(OSINT), "-t", *targets, "-n", name, "-y", "--no-deps", "-c", "scope.report_distance=1"]
    cmd += ["-m", *modules] if modules else ["-f", "passive"]
    SCANS_DIR.mkdir(exist_ok=True)
    log_path = SCANS_DIR / f"{name}.console.log"
    with open(log_path, "w", encoding="utf-8") as log:
        # preexec_fn only resets a signal handler - no locks, safe with the server's threads
        proc = subprocess.Popen(
            cmd, cwd=str(ROOT), stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True, env=_child_env(), preexec_fn=_restore_sigint,  # noqa: PLW1509
        )
    with _lock:
        _jobs[name] = {"proc": proc, "targets": targets, "modules": modules, "started": time.time(), "log": log_path,
                       "meta": dict(meta or {})}  # fmt: skip
    if on_finish is not None:
        threading.Thread(target=_watch, args=(name, proc, on_finish), daemon=True).start()
    return job_info(name)


def _watch(name, proc, on_finish):
    rc = proc.wait()
    try:
        on_finish(name, rc)
    except Exception as e:  # noqa: BLE001 - post-processing must never kill the server
        import sys

        sys.stderr.write(f"  post-processing of scan {name} failed: {e}\n")


def _tail(path, n=12):
    try:
        with open(path, "rb") as fh:
            fh.seek(0, 2)
            fh.seek(max(0, fh.tell() - 8000))
            text = fh.read().decode("utf-8", errors="replace")
    except OSError:
        return []
    return [ANSI_RE.sub("", x) for x in text.splitlines()[-n:]]


def job_info(name):
    j = _jobs.get(name)
    if j is None:
        return None
    rc = j["proc"].poll()
    return {
        "name": name,
        "targets": j["targets"],
        "modules": j["modules"],
        "started": j["started"],
        "running": rc is None,
        "returncode": rc,
        "stopping": j.get("stopping", False),
        "meta": j.get("meta", {}),
        "log": _tail(j["log"]),
    }


def list_jobs():
    with _lock:
        names = sorted(_jobs, key=lambda n: _jobs[n]["started"], reverse=True)
    return [job_info(n) for n in names]


def stop_scan(name):
    j = _jobs.get(name)
    if j is None or j["proc"].poll() is not None:
        raise ScanError("scan is not running", 404)
    # on Ctrl+C BBoT finishes the scan cleanly and writes its output
    os.killpg(j["proc"].pid, signal.SIGINT)
    j["stopping"] = True
    threading.Thread(target=_ensure_stopped, args=(j["proc"],), daemon=True).start()
    return job_info(name)


def _ensure_stopped(proc, grace=60):
    """If BBoT has not exited `grace` seconds after SIGINT (stuck in API retries), SIGTERM the group."""
    try:
        proc.wait(grace)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGTERM)


def list_scans():
    scans = []
    if SCANS_DIR.is_dir():
        for d in sorted(SCANS_DIR.iterdir()):
            out = d / "output.json"
            if d.is_dir() and out.is_file():
                try:
                    with open(out, encoding="utf-8") as fh:
                        events = sum(1 for _ in fh)
                except OSError:
                    events = 0
                scans.append({"name": d.name, "events": events, "mtime": int(out.stat().st_mtime)})
    running = running_job()
    for s in scans:
        s["running"] = s["name"] == running
    scans.sort(key=lambda s: s["mtime"], reverse=True)
    return scans
