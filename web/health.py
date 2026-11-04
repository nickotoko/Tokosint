#!/usr/bin/env python3
"""Deep source health check: a real BBoT scan verifies that a source answers and returns data.

One test scan of neutral targets (example.com - the IANA example domain, 1.1.1.1 - Cloudflare public DNS)
with all source modules. For each source we record what actually happened:

  ok       the source ran and returned data (produced > 0)
  nodata   the source ran without errors but returned nothing (produced == 0)
  down     the source failed (API/network error) or did not start for a reason other than a key
  nokey    the source needs an API key and secrets.yml has none (the module did not start)
  local    the source has no external endpoint (DNS/local logic) - no real request needed

WARNING: the deep check makes REAL requests and spends source quotas (e.g. hunter.io - 50 searches/month).
That is why it runs automatically once a day; run it manually with `bin/healthcheck`.

The result is written to web/health.json and served at /api/health.
"""

import asyncio
import json
import shutil
import tempfile
import time
from pathlib import Path

import yaml

WEB_DIR = Path(__file__).resolve().parent
ROOT = WEB_DIR.parent
HEALTH_FILE = WEB_DIR / "health.json"
SECRETS = ROOT / "config" / "secrets.yml"
PROBES = WEB_DIR / "health_probes.json"
TEST_TARGETS = ["example.com", "1.1.1.1"]
TIMEOUT = 420  # hard ceiling for the whole scan, seconds
TTL = 24 * 3600  # automatic run once a day


def configured_keys():
    """Modules with a non-empty api_key in secrets.yml (only whether it is set, never the value)."""
    keyed = set()
    if not SECRETS.is_file():
        return keyed
    try:
        data = yaml.safe_load(SECRETS.read_text()) or {}
    except yaml.YAMLError:
        return keyed
    for name, conf in (data.get("modules") or {}).items():
        if isinstance(conf, dict) and str(conf.get("api_key") or "").strip():
            keyed.add(name)
    return keyed


def local_modules():
    """Modules without an external endpoint (null in health_probes.json) - not probed with a request."""
    try:
        probes = json.loads(PROBES.read_text())
    except (OSError, ValueError):
        return set()
    return {k for k, v in probes.items() if k != "_comment" and v is None}


async def _run_scan(sources, timeout):
    from bbot.scanner import Scanner

    tmp = tempfile.mkdtemp(prefix="osint-health-")
    try:
        scan = Scanner(
            *TEST_TARGETS,
            modules=sources,
            name="healthcheck",
            output_dir=tmp,
            config={
                "deps": {"behavior": "disable"},
                "cloudcheck": False,
                "scope": {"report_distance": 1, "search_distance": 1},
            },
        )
        try:
            await asyncio.wait_for(scan.async_start_without_generator(), timeout)
        except asyncio.TimeoutError:
            await scan.stop()
        return scan
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _classify(name, auth_required, scan, keyed, local):
    if name in local:
        return {"status": "local", "detail": "no external endpoint"}
    mod = scan.modules.get(name)
    if mod is None:
        if auth_required and name not in keyed:
            return {"status": "nokey", "detail": "needs an API key, none in secrets.yml"}
        return {"status": "down", "detail": "module did not start (setup/ping)"}
    if getattr(mod, "errored", False):
        return {"status": "down", "detail": "error during the request (API/network/quota)"}
    st = scan.stats.module_stats.get(name)
    produced = getattr(st, "produced_total", 0) if st else 0
    consumed = getattr(st, "consumed_total", 0) if st else 0
    if produced > 0:
        return {"status": "ok", "detail": f"returned data: {produced} events"}
    if consumed > 0:
        return {"status": "nodata", "detail": "ran, returned no data"}
    return {"status": "nodata", "detail": "received no suitable events in the test"}


def run_all():
    import sys

    sys.path.insert(0, str(WEB_DIR))
    from _build import build_sources

    sources = build_sources()
    names = [s["name"] for s in sources]
    keyed = configured_keys()
    local = local_modules()

    testable = [n for n in names if n not in local]
    scan = asyncio.run(_run_scan(testable, TIMEOUT))

    results = {}
    now = int(time.time())
    for s in sources:
        res = _classify(s["name"], s["auth_required"], scan, keyed, local)
        res["checked_at"] = now
        results[s["name"]] = res

    out = {"checked_at": now, "mode": "deep", "targets": TEST_TARGETS, "sources": results}
    tmp = HEALTH_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(out, ensure_ascii=False, indent=2))
    tmp.replace(HEALTH_FILE)
    return out


def load():
    if HEALTH_FILE.is_file():
        try:
            return json.loads(HEALTH_FILE.read_text())
        except ValueError:
            pass
    return {"checked_at": 0, "sources": {}}


def is_stale():
    return (time.time() - load().get("checked_at", 0)) > TTL


if __name__ == "__main__":
    print("Deep health check: real requests to sources (spends quota). This takes a few minutes...")
    out = run_all()
    counts = {}
    for r in out["sources"].values():
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print("health.json updated:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
