#!/usr/bin/env python3
"""Tokosint MCP server: read scan data and run scans over the Model Context Protocol.

A thin wrapper over the same web/ modules the HTTP backend uses (scans, overrides, risk, store), so an MCP client
(Claude Desktop/Code) sees exactly what the web UI shows. Transports:

    mcp_server.py stdio                 # local client launches this as a subprocess (default)
    mcp_server.py http [port]           # streamable-HTTP on 127.0.0.1:<port> (default 8778), e.g. in a container

Tools:
  read  - list_scans, scan_report, get_findings (filter by risk/status/type, paginated), get_false_findings,
          get_screenshots, get_sources, get_asset (one finding with its discovery chains)
  act   - start_scan, stop_scan, scan_status, set_status_override

Runs on bbot/.venv (needs the `mcp` dependency group); findings are read the same way as /api/scan, so the risk
levels, manual status overrides and enrichments all apply. Large scans are capped per call (see MAX_FINDINGS)."""

import os
import sys
from pathlib import Path

WEB_DIR = Path(__file__).resolve().parent
ROOT = WEB_DIR.parent
sys.path.insert(0, str(WEB_DIR))

import eventdb
import overrides
import risk
import store
from _build import build_sources
from bbot.core.modules import MODULE_LOADER
from mcp.server.fastmcp import FastMCP

import scans

MAX_FINDINGS = 500  # per get_findings call; filter down rather than dumping a whole scan into the model

# Fields returned for a finding in a list (the full record, incl. discovery chains, is in get_asset).
SLIM_FIELDS = ("type", "data", "status", "risk", "risk_reasons", "sources", "tags", "hosts", "ports",
               "http_status", "last_seen", "scan_date", "enriched_by", "details")  # fmt: skip


def known_sources():
    return {s["name"] for s in build_sources()}


def _scan_or_error(name):
    """(path, None) for a readable scan, or (None, {"error": ...})."""
    path = scans.safe_scan_path(name)
    if path is None:
        return None, {"error": f"scan {name!r} not found"}
    return path, None


def _findings(name, path):
    """The scan's findings exactly as the Analysis view builds them: aggregated + overrides + risk + enrichments."""
    return risk.annotate(
        overrides.apply(name, scans.aggregate_scan(path, include_enrichments=True))
    )


def _slim(f):
    return {k: f.get(k) for k in SLIM_FIELDS if f.get(k) not in (None, [], {}, "")}


mcp = FastMCP(
    "tokosint",
    instructions=(
        "Tokosint OSINT toolkit: query scans and findings and run new scans. A finding has a type (DNS_NAME, URL, "
        "OPEN_TCP_PORT, TECHNOLOGY, FINDING, ...), a value, a validity status (valid / historical / false) and a "
        "risk level (critical / high / medium / low / none). Start with list_scans, then get_findings(scan=...) "
        "filtered by risk or type; use get_asset for one finding's full detail and how it was discovered."
    ),
)


# ---------- read ----------


@mcp.tool()
def list_scans() -> list:
    """List all scans (name, number of events, start date, targets, whether it is an enrichment, running state)."""
    return scans.list_scans()


@mcp.tool()
def scan_report(scan: str) -> dict:
    """Per-source report for a scan: what and how much each source found, totals by type and validity status,
    and any source problems (rate limits, quota, errors). `scan` is a scan name from list_scans."""
    producers = {s["name"] for s in build_sources() if s["produced_events"]}
    report = scans.scan_report(scan, producers)
    return report if report is not None else {"error": f"scan {scan!r} not found"}


@mcp.tool()
def get_findings(
    scan: str,
    risk_level: str = "",
    status: str = "",
    type: str = "",
    query: str = "",
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """Findings of a scan, filtered and paginated (the same data as the web Analysis view).

    risk_level: critical|high|medium|low|none (exact level). status: valid|historical|false. type: an event type
    (DNS_NAME, URL, OPEN_TCP_PORT, TECHNOLOGY, FINDING, EMAIL_ADDRESS, ...). query: substring match on the value.
    Returns {scan, total, returned, offset, risk_counts, findings:[...]}; at most 500 per call. Use get_asset for
    one finding's full record and discovery chains."""
    path, err = _scan_or_error(scan)
    if err:
        return err
    findings = _findings(scan, path)
    counts = risk.counts(findings)
    rl = (risk_level or "").strip().lower()
    st = (status or "").strip().lower()
    ty = (type or "").strip()
    q = (query or "").strip().lower()
    sel = []
    for f in findings:
        if rl:
            fr = f.get("risk")
            if rl == "none":
                if fr is not None:
                    continue
            elif fr != rl:
                continue
        if st and (f.get("status") or "") != st:
            continue
        if ty and f.get("type") != ty:
            continue
        if q and q not in str(f.get("data", "")).lower():
            continue
        sel.append(f)
    total = len(sel)
    offset = max(0, int(offset))
    limit = max(1, min(int(limit), MAX_FINDINGS))
    page = [_slim(f) for f in sel[offset : offset + limit]]
    return {"scan": scan, "total": total, "returned": len(page), "offset": offset,
            "risk_counts": counts, "findings": page}  # fmt: skip


@mcp.tool()
def get_false_findings(scan: str, limit: int = 200) -> dict:
    """Findings the validation dropped as false, each with the reason (useful for tuning the validation rules)."""
    path, err = _scan_or_error(scan)
    if err:
        return err
    false = [f for f in _findings(scan, path) if f.get("status") == "false"]
    page = [{"type": f["type"], "data": f["data"], "sources": f.get("sources"),
             "false_reasons": f.get("false_reasons")} for f in false[:max(1, int(limit))]]  # fmt: skip
    return {"scan": scan, "total": len(false), "returned": len(page), "findings": page}


@mcp.tool()
def get_screenshots(scan: str = "") -> dict:
    """gowitness screenshots. With no scan, every screenshot of every scan; with a scan, that scan and its
    enrichments. Each has the page URL, final URL, HTTP code, page title, validity status and the image path
    (served by the web UI at /api/screenshot/<scan>/<path>)."""
    return scans.list_screenshots(scan or None)


@mcp.tool()
def get_sources() -> list:
    """The scan sources (BBoT modules): name, input/output event types, whether a key is set, free-tier quota."""
    return build_sources()


@mcp.tool()
def get_asset(scan: str, type: str, data: str) -> dict:
    """One finding in full: its record (sources, tags, risk, hosts/ports, screenshots, status override) and every
    distinct way it was discovered (seed -> ... -> finding, with the status of each step). `type` and `data` are
    a finding's type and value from get_findings."""
    path, err = _scan_or_error(scan)
    if err:
        return err
    finding = next(
        (
            f
            for f in _findings(scan, path)
            if f.get("type") == type and f.get("data") == data
        ),
        None,
    )
    if finding is None:
        return {"error": f"finding {type} {data!r} not found in scan {scan!r}"}
    return {"finding": finding, "discovery": scans.discovery_chains(path, type, data)}


# ---------- act ----------


@mcp.tool()
def start_scan(targets: list, name: str = "", modules: list | None = None) -> dict:
    """Start a scan. targets: domains and/or IPs/CIDRs. name: optional scan name (auto if empty). modules: source
    names (from get_sources); empty = the whole passive set. The pool runs up to TOKOSINT_MAX_SCANS at once and
    queues the rest; the returned job has state "running" or "queued" (with queue_position)."""
    payload = {"targets": targets, "name": name, "modules": modules or []}
    try:
        return scans.start_scan(payload, known_sources())
    except scans.ScanError as e:
        return {"error": str(e), "code": e.code}


@mcp.tool()
def stop_scan(name: str) -> dict:
    """Stop a running scan (BBoT finishes writing its output) or drop a queued one before it starts."""
    try:
        return scans.stop_scan(name)
    except scans.ScanError as e:
        return {"error": str(e), "code": e.code}


@mcp.tool()
def scan_status(name: str = "") -> dict:
    """Scan jobs this server knows about. With a name, that one job; without, the pool capacity plus every job
    (running, queued, finished) with a tail of its log."""
    if name:
        info = scans.job_info(name)
        return info if info is not None else {"error": f"no job named {name!r}"}
    return {"pool": scans.pool_status(), "jobs": scans.list_jobs()}


@mcp.tool()
def set_status_override(
    scan: str, type: str, data: str, status: str, note: str = ""
) -> dict:
    """Manually set a finding's status: valid | historical | false (or empty to revert to the computed status).
    The change is logged with the evidence snapshot; if the scan belongs to a company, its timeline is rebuilt.
    `type` and `data` identify the finding (as in get_findings)."""
    try:
        return overrides.set_status(
            {"scan": scan, "type": type, "data": data, "status": status, "note": note}
        )
    except store.StoreError as e:
        return {"error": str(e), "code": e.code}


@mcp.tool()
def delete_scan_files(scan: str) -> dict:
    """Free disk space on a large scan: import its events into the database (if not already) and delete the big
    output.json and validity_false.jsonl. Every read keeps working from the database and the screenshots and logs
    are kept. Returns the deleted files and the bytes freed."""
    try:
        eventdb.import_scan(scan)
        return eventdb.delete_files(scan)
    except store.StoreError as e:
        return {"error": str(e), "code": e.code}


def main():
    store.init()
    eventdb.init()
    MODULE_LOADER.preloaded()  # warm the module registry (build_sources needs it)
    args = sys.argv[1:]
    transport = args[0] if args else os.environ.get("TOKOSINT_MCP_TRANSPORT", "stdio")
    if transport == "http":
        port = (
            int(args[1])
            if len(args) > 1
            else int(os.environ.get("TOKOSINT_MCP_PORT", "8778"))
        )
        mcp.settings.host = os.environ.get("TOKOSINT_MCP_HOST", "127.0.0.1")
        mcp.settings.port = port
        sys.stderr.write(
            f"Tokosint MCP (streamable-http) on http://{mcp.settings.host}:{port}{mcp.settings.streamable_http_path}\n"
        )
        mcp.run(transport="streamable-http")
    elif transport == "stdio":
        mcp.run(transport="stdio")
    else:
        sys.exit(f"unknown transport {transport!r}: use 'stdio' or 'http'")


if __name__ == "__main__":
    main()
