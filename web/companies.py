"""Company scans: starting a scan for a company, post-processing a finished scan (registry diff -> timeline ->
Telegram alert), attaching existing scans, and the built-in cron scheduler.

Only FINISHED scans are ingested: an aborted or failed scan has partial data and would corrupt the baseline
(and later produce false "new" findings). Attaching existing scans rebuilds the company's registry and timeline
from all its scans in chronological order, without alerts.
"""

import re
import sys
import threading
import time
from datetime import datetime

import cronexpr
import notify
import scans
import store

BASE_URL = ""  # set by the server: link to the timeline in Telegram messages
SCHEDULER_TICK = 30
_tick_lock = threading.Lock()


def _log(msg):
    sys.stderr.write(f"  {msg}\n")


def scan_name_for(company):
    slug = re.sub(r"[^a-z0-9]+", "_", company["name"].lower()).strip("_")[:30] or "company"
    return f"{slug}_{time.strftime('%Y%m%d_%H%M')}"


def start_company_scan(company_id, modules, known_sources, schedule_id=None, name=None, targets=None):
    """Starts a scan linked to a company; targets default to the company's targets."""
    company = store.get_company(company_id)
    targets = targets or company["targets"]
    if not targets:
        raise store.StoreError(f"company {company['name']} has no targets")
    name = name or scan_name_for(company)
    job = scans.start_scan(
        {"targets": targets, "name": name, "modules": modules},
        known_sources,
        on_finish=process_scan,
        meta={"company_id": company_id, "company": company["name"], "schedule_id": schedule_id},
    )
    store.link_scan(job["name"], company_id, schedule_id, job["started"])
    return job


def _scan_status(path):
    status = None
    for e in scans.read_events(path):
        if e.get("type") == "SCAN":
            status = (e.get("data_json") or {}).get("status") or status
    return status


def _ingest(name, alert):
    path = scans.safe_scan_path(name)
    if path is None:
        store.set_alert_result(name, "no output: not ingested")
        return None
    status = _scan_status(path)
    if status != "FINISHED":
        store.set_alert_result(name, f"scan {status or 'unfinished'}: not ingested")
        return None
    import overrides  # overrides imports this module

    findings = overrides.apply(name, scans.aggregate_scan(path, with_false=False))
    result = store.ingest(name, findings, scans.scan_started_at(path))
    if alert:
        company = store.get_company(result["company_id"])
        store.set_alert_result(name, notify.alert_new_findings(company, name, result, BASE_URL))
    return result


def process_scan(name, returncode=0):
    """Called when a scan process exits (scans.start_scan on_finish)."""
    if store.scan_link(name) is None:
        return
    result = _ingest(name, alert=True)
    if result:
        _log(f"scan {name}: {'baseline' if result['baseline'] else 'new'} findings: {len(result['new'])}")


def attach_scans(company_id, names):
    """Links existing scans to a company and rebuilds its registry and timeline (no alerts)."""
    store.get_company(company_id)
    for name in names:
        path = scans.safe_scan_path(name)
        if path is None:
            raise store.StoreError(f"scan {name} not found", 404)
        store.link_scan(name, company_id, started_at=scans.scan_started_at(path))
    return rebuild(company_id)


# Bump when the finding key or status of aggregated findings changes (e.g. v2: TECHNOLOGY keyed by the technology,
# not its host; manual status overrides): registries built by an older version are rebuilt once, without alerts -
# otherwise the next scan would report every re-keyed finding as new.
REGISTRY_VERSION = "2"


def migrate_registries():
    if store.get_setting("registry_version") == REGISTRY_VERSION:
        return []
    done = [(co["id"], rebuild(co["id"])) for co in store.list_companies()]
    store.set_setting("registry_version", REGISTRY_VERSION)
    if done:
        _log(f"registry v{REGISTRY_VERSION}: rebuilt {len(done)} companies")
    return done


def rebuild(company_id):
    store.reset_registry(company_id)
    done = []
    for link in sorted(store.company_scans(company_id), key=lambda s: s["started_at"] or 0):
        result = _ingest(link["scan"], alert=False)
        done.append({"scan": link["scan"], "ingested": bool(result), "new": len(result["new"]) if result else 0})
    return done


# ---------- scheduler ----------


def schedule_payload(data, known_sources):
    cron = cronexpr.validate(data.get("cron"))
    modules = data.get("modules") or []
    if not isinstance(modules, list) or any(m not in known_sources for m in modules):
        raise store.StoreError("unknown source in the module list")
    return {"company_id": data.get("company_id"), "cron": cron, "modules": modules, "enabled": data.get("enabled", True)}


def next_run_ts(cron):
    return cronexpr.next_run(cron).timestamp()


def tick(known_sources_fn):
    """One scheduler pass: mark due schedules as pending, start a pending one if no scan is running."""
    if not _tick_lock.acquire(blocking=False):
        return
    try:
        now = time.time()
        for s in store.list_schedules():
            if not s["enabled"]:
                continue
            if s["next_run"] is None or s["next_run"] <= now:
                # a missed run (server was down) runs once; the next one is computed from now
                store.update_schedule_run(s["id"], pending=1, next_run=next_run_ts(s["cron"]))
        if scans.running_job():
            return
        for s in store.list_schedules():
            if not (s["enabled"] and s["pending"]):
                continue
            try:
                job = start_company_scan(s["company_id"], s["modules"], known_sources_fn(), schedule_id=s["id"])
                store.update_schedule_run(s["id"], pending=0, last_run=now, last_scan=job["name"])
                _log(f"schedule {s['id']} ({s['company']}, {s['cron']}): started {job['name']}")
            except scans.ScanError as e:
                if e.code == 409 and "already running" in str(e):
                    return  # stays pending until the running scan finishes
                store.update_schedule_run(s["id"], pending=0, last_run=now, last_scan=f"error: {e}")
            except store.StoreError as e:
                store.update_schedule_run(s["id"], pending=0, last_run=now, last_scan=f"error: {e}")
            return  # one scan at a time
    finally:
        _tick_lock.release()


def scheduler_loop(known_sources_fn):
    while True:
        try:
            tick(known_sources_fn)
        except Exception as e:  # noqa: BLE001 - the loop must survive any error
            _log(f"scheduler error: {e}")
        time.sleep(SCHEDULER_TICK)


def describe_next(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else ""
