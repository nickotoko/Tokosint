"""Scans in scans/: list, findings, per-source report and starting new scans through bin/osint.

Standard library only. Scan data stays in scans/ (gitignored).
"""

import contextlib
import datetime
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
from urllib.parse import urlsplit

import quota
from validity import compute_status

WEB_DIR = Path(__file__).resolve().parent
ROOT = WEB_DIR.parent
SCANS_DIR = ROOT / "scans"
OSINT = ROOT / "bin" / "osint"

MAX_TARGETS = 20
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,59}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$"
)
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


def scan_head(path):
    """(start time, targets) of a scan from the SCAN event on the first line of its output.json, or, once the scan
    has been imported and its file deleted, from the import record in the database."""
    if not Path(path).is_file():
        import eventdb

        try:
            rec = eventdb.import_record(_name_of(path))
        except Exception:  # noqa: BLE001
            rec = None
        if rec is not None:
            return rec.get("started_at"), list(rec.get("targets") or [])
        return None, []
    try:
        with open(path, encoding="utf-8") as fh:
            first = json.loads(fh.readline() or "{}")
    except (OSError, ValueError):
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


def scan_started_at(path):
    """Start time (unix) of a scan from the SCAN event in its output.json, or None."""
    return scan_head(path)[0]


def safe_scan_path(name):
    """The scan's output.json path, or None. Returns the (conceptual) path when the file was deleted after an
    import: the events are then read from the database via events_for, so downstream readers work unchanged."""
    d = safe_scan_dir(name)
    if d is None:
        return None
    out = d / "output.json"
    if out.is_file():
        return out
    return out if _imported(name) else None


SCREENSHOT_TYPES = {".jpeg": "image/jpeg", ".jpg": "image/jpeg", ".png": "image/png"}


def screenshot_file(scan, rel):
    """A gowitness screenshot of a scan: <scan>/gowitness/screenshots/<file>, image types only; None otherwise
    (protects against path traversal: the path must stay inside the scan's screenshots folder)."""
    d = safe_scan_dir(scan)
    if d is None or not rel:
        return None
    base = (d / "gowitness" / "screenshots").resolve()
    try:
        f = (d / rel).resolve()
        f.relative_to(base)
    except (ValueError, OSError):
        return None
    if f.suffix.lower() not in SCREENSHOT_TYPES or not f.is_file():
        return None
    return f


def _scan_root(d):
    """The original scan of an enrichment (enrich.json "parent", followed up the chain); the scan itself otherwise."""
    name, seen = d.name, set()
    while name not in seen:
        seen.add(name)
        try:
            parent = json.loads((SCANS_DIR / name / "enrich.json").read_text()).get(
                "parent"
            )
        except (OSError, ValueError):
            parent = None
        if not parent:
            return name
        name = parent
    return name


def list_screenshots(scan=None):
    """Every gowitness screenshot of every scan (or of one scan with its enrichments), with the file present.

    {"scans": [{name, root, count}], "shots": [{scan, root, path, url, page, status_code, title, status, at}]};
    root - the original scan (enrichments are shown with it), page - the URL that was visited, url - where the
    browser ended up, status - the validity status of the screenshot."""
    want = _scan_root(SCANS_DIR / scan) if scan else None
    shots, per_scan = [], {}
    if not SCANS_DIR.is_dir():
        return {"scans": [], "shots": []}
    for d in sorted(SCANS_DIR.iterdir()):
        if not (
            d.is_dir()
            and (d / "gowitness" / "screenshots").is_dir()
            and ((d / "output.json").is_file() or _imported(d.name))
        ):
            continue
        root = _scan_root(d)
        if want and root != want:
            continue
        events = events_for(d / "output.json")
        urls = {e.get("id"): e for e in events if e.get("type") == "URL"}
        for e in events:
            if e.get("type") != "WEBSCREENSHOT":
                continue
            data = (
                e.get("data")
                if isinstance(e.get("data"), dict)
                else (e.get("data_json") or {})
            )
            if not data.get("path") or screenshot_file(d.name, data["path"]) is None:
                continue
            tags = e.get("tags") or []
            status = next(
                (t[len("validity-") :] for t in tags if t.startswith("validity-")), None
            )
            page = urls.get(e.get("parent"))
            # the code the browser got; screenshots taken before gowitness recorded it fall back to the http
            # module's answer for the same URL (the first answer, before redirects)
            code, code_from = data.get("status_code"), "browser"
            if not code and page:
                code = next(
                    (
                        int(t[7:])
                        for t in page.get("tags") or []
                        if t.startswith("status-") and t[7:].isdigit()
                    ),
                    None,
                )
                code_from = "http" if code else None
            shots.append({"scan": d.name, "root": root, "path": data["path"], "url": data.get("url"),
                          "page": (asset_data(page) if page else None) or data.get("url"), "status_code": code,
                          "code_from": code_from if code else None, "title": data.get("title"), "status": status,
                          "requested_url": data.get("requested_url"), "status_reason": data.get("status_reason"),
                          "redirect_chain": data.get("redirect_chain"), "at": e.get("timestamp")})  # fmt: skip
            per_scan[d.name] = per_scan.get(d.name, 0) + 1
    shots.sort(key=lambda x: (x["root"], -(x["at"] or 0), x["url"] or ""))
    scans_out = [
        {"name": n, "root": _scan_root(SCANS_DIR / n), "count": c}
        for n, c in sorted(per_scan.items())
    ]
    return {"scans": scans_out, "shots": shots}


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


def _name_of(path):
    """The scan name of an output.json path (scans/<name>/output.json)."""
    return Path(path).parent.name


def _imported(name):
    """True if the scan's events are in the database. Any DB error (e.g. the tables are not set up in a unit test)
    means "not imported", so callers fall back to reading the files."""
    import eventdb

    try:
        return eventdb.is_imported(name)
    except Exception:  # noqa: BLE001 - fall back to the file on any DB problem
        return False


def events_for(path):
    """Events of the scan whose output is `path`: from the database once the scan is imported, else from the file.
    Lets aggregation, chains and the report run unchanged after the large output.json has been deleted."""
    import eventdb

    name = _name_of(path)
    if _imported(name):
        return eventdb.events_of(name)
    return read_events(path) if Path(path).is_file() else []


def false_for(path):
    """False findings of the scan whose output is `path` (validity_false.jsonl), from the database or the file."""
    import eventdb

    name = _name_of(path)
    if _imported(name):
        return eventdb.false_of(name)
    log = Path(path).parent / "validity_false.jsonl"
    return read_events(log) if log.is_file() else []


def asset_data(e):
    """String form of an event's finding (for dicts - host/url/name/...).

    TECHNOLOGY is the technology itself (its host and port are separate fields, see asset_host_port),
    so the same software on several hosts/ports is one finding, not a copy of the host."""
    d = e.get("data")
    if d is None:
        d = e.get("data_json")
    if d is None:
        return None
    if isinstance(d, str):
        return d
    if e.get("type") == "TECHNOLOGY" and d.get("technology"):
        return str(d["technology"])
    # always a string: ASN data is a number, while the UI sorts and searches strings
    v = (
        d.get("host")
        or d.get("url")
        or d.get("name")
        or d.get("asn")
        or d.get("ip")
        or d.get("description")
    )
    return str(v) if v is not None else json.dumps(d, ensure_ascii=False)


def source_name(module):
    """DNS records (A, NS, MX...) come from dummy modules - this is dnsresolve's live resolution."""
    if module and module != "SEED" and module.isupper():
        return "dnsresolve"
    return module


def asset_host_port(e):
    """(host, port) of an event: OPEN_TCP_PORT host:port, URL, TECHNOLOGY seen on a port."""
    host = e.get("host")
    port = e.get("port")
    d = e.get("data_json") if isinstance(e.get("data_json"), dict) else None
    if d is not None:
        host = host or d.get("host")
        port = port or d.get("port")
    if port is None and d is not None and d.get("url"):
        with contextlib.suppress(ValueError):
            u = urlsplit(d["url"])
            port = u.port or {"https": 443, "http": 80}.get(u.scheme)
    if port is not None:
        try:
            port = int(port)
        except (TypeError, ValueError):
            port = None
    return (str(host) if host else None), port


DETAIL_FIELDS = ("description", "severity", "confidence", "url", "host", "path", "name", "platform", "profile_name",
                 "technology", "asn", "country", "city", "subnet", "redirect_location")  # fmt: skip
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


# Source dates that modules wrote into the discovery context before events had last_seen (older scans):
# "seen 2017-06-24 .. 2026-11-06" (robtex, circl_pdns), "observed 2024-05-01 .. 2024-06-01" (shodan_idb),
# "(seen 2024-05-01)" (netlas). The last date of the range is the last observation.
_CONTEXT_DATES = re.compile(
    r"\b(?:seen|observed) (\d{4}-\d{2}-\d{2})(?: \.\. (\d{4}-\d{2}-\d{2}))?"
)


def context_last_seen(context):
    m = _CONTEXT_DATES.search(str(context or ""))
    if not m:
        return None
    try:
        day = datetime.datetime.strptime(m.group(2) or m.group(1), "%Y-%m-%d").replace(
            tzinfo=datetime.timezone.utc
        )
    except ValueError:
        return None
    return day.timestamp()


_REGISTRABLE = {}


def is_registrable(etype, data):
    """A DNS name that is itself a registrable domain (eTLD+1 by the Public Suffix List): example.com,
    example.co.uk - "second-level domains" in the UI; www.example.com is not."""
    if etype not in ("DNS_NAME", "DNS_NAME_UNRESOLVED"):
        return False
    name = str(data).lower().rstrip(".")
    if name not in _REGISTRABLE:
        from bbot.core.helpers.misc import tldextract

        try:
            _REGISTRABLE[name] = tldextract(name).top_domain_under_public_suffix == name
        except Exception:  # noqa: BLE001 - a malformed name is just not a domain
            _REGISTRABLE[name] = False
    return _REGISTRABLE[name]


def enrichment_outputs(path):
    """[(scan name, output.json)] of the finished enrichments of the scan at `path` (web/enrich.py)."""
    import enrich  # enrich imports this module

    out = []
    for name in enrich.children(Path(path).parent.name):
        p = safe_scan_path(name)
        if p is not None:
            out.append((name, p))
    return out


def aggregate_scan(path, with_false=True, include_enrichments=False):
    """Scan JSONL -> list of findings [{type, data, sources, tags, last_seen, scan_date, status, details, contexts,
    false_reasons}].

    last_seen - the latest date the sources themselves report for the finding (pDNS time_last, FOFA lastupdatetime,
    Shodan banner timestamp...), None when no source gives a date; scan_date - when the scan ran (its start time,
    the time of discovery otherwise).

    status - valid / historical / false across all discovery paths (web/validity.py), None - an untagged scan.
    with_false - add false findings from validity_false.jsonl (they are not in the scan output): status false
    unless another path confirmed the finding, with the reason in false_reasons.
    include_enrichments - add the findings of the scan's enrichments (new sources run over its findings later):
    their seeds are the scan's own findings and are not counted again; "enriched_by" names the enrichment scans."""
    events = events_for(path)
    extra = (
        [(name, events_for(p), p) for name, p in enrichment_outputs(path)]
        if include_enrichments
        else []
    )
    status = compute_status(events + [e for _, evs, _ in extra for e in evs])
    by_key = {}
    scan_date = scan_started_at(path)
    if scan_date is None:
        stamps = [
            e["timestamp"]
            for e in events
            if isinstance(e.get("timestamp"), (int, float))
        ]
        scan_date = min(stamps) if stamps else None
    # domains promoted into scope by related_domains (a subsidiary, a second brand): uuid of the promotion -> domain
    promoted = {e["uuid"]: str(e.get("data")) for e in events
                if e.get("module") == "related_domains" and e.get("type") == "DNS_NAME" and e.get("uuid")}  # fmt: skip

    def asset(etype, data):
        key = f"{etype}\x00{data}"
        a = by_key.get(key)
        if a is None:
            a = {"type": etype, "data": data, "sources": set(), "tags": set(), "last_seen": None, "status": None,
                 "details": {}, "contexts": {}, "false_reasons": [], "hosts": set(), "ports": set(),
                 "on": {}, "via": None, "enriched_by": set(), "screenshots": {}, "codes": set()}  # fmt: skip
            by_key[key] = a
        return a

    groups = [(None, events, {})] + [
        (name, evs, {e["uuid"]: e for e in evs if e.get("uuid")})
        for name, evs, _ in extra
    ]
    original = set()
    for enrichment, group, group_uuids in groups:
        if enrichment and not original:
            original = set(by_key)
        by_id = {e.get("id"): e for e in group if e.get("type") == "URL"}
        for e in group:
            etype = e.get("type")
            if not etype or etype == "SCAN":
                continue
            if enrichment and "seed" in (e.get("tags") or []):
                # a seed of an enrichment is a finding of the original scan: already counted
                continue
            data = asset_data(e)
            if data is None:
                continue
            a = asset(etype, data)
            # "via": the related domains every discovery path of the finding goes through (empty - the target's own)
            chain = e.get("parent_chain") or []
            via = {promoted[u] for u in chain if u in promoted} if promoted else set()
            if enrichment:
                # the path continues from the seed: the related domains of the seed's finding in the original scan
                seed = group_uuids.get(chain[0]) if chain else None
                seed_asset = (
                    by_key.get(f"{seed.get('type')}\x00{asset_data(seed)}")
                    if seed
                    else None
                )
                via |= set((seed_asset or {}).get("via") or ())
                if f"{etype}\x00{data}" not in original:
                    # new to the original scan (not a re-observation, e.g. the DNS records of a seed)
                    a["enriched_by"].add(enrichment)
            a["via"] = via if a["via"] is None else a["via"] & via
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
            host, port = asset_host_port(e)
            if host:
                a["hosts"].add(host)
            if port:
                a["ports"].add(port)
            if etype == "TECHNOLOGY" and host:
                # where the technology was seen: host -> ports (empty: the source gave no port)
                on = a["on"].setdefault(host, set())
                if port:
                    on.add(port)
            if etype == "WEBSCREENSHOT":
                # gowitness: the image file lives in the scan that took it (an enrichment has its own folder);
                # the screenshot also goes to the URL it shows, so the URL's card and the gallery can show it
                d = (
                    e.get("data")
                    if isinstance(e.get("data"), dict)
                    else (e.get("data_json") or {})
                )
                # a failed shot of an older gowitness run points at the folder: only real image files count
                if (
                    d.get("path")
                    and screenshot_file(enrichment or path.parent.name, d["path"])
                    is not None
                ):
                    shot = {"scan": enrichment or path.parent.name, "path": d["path"], "url": d.get("url") or data,
                            "status_code": d.get("status_code"), "title": d.get("title"),
                            "requested_url": d.get("requested_url"), "status_reason": d.get("status_reason"),
                            "redirect_chain": d.get("redirect_chain")}  # fmt: skip
                    if d.get("status_code"):
                        a["codes"].add(int(d["status_code"]))
                    a["screenshots"].setdefault(shot["path"], shot)
                    parent = by_id.get(e.get("parent"))
                    target = (
                        by_key.get(f"URL\x00{asset_data(parent)}")
                        if parent is not None
                        else None
                    )
                    if target is not None:
                        target["screenshots"].setdefault(shot["path"], shot)
            ctx = e.get("discovery_context")
            if ctx and len(a["contexts"]) < MAX_CONTEXTS:
                a["contexts"].setdefault(
                    f"{module}\x00{ctx}", {"module": module, "context": ctx[:500]}
                )
            seen = e.get("last_seen")
            if seen is None:
                seen = context_last_seen(e.get("discovery_context"))
            if isinstance(seen, (int, float)) and (
                a["last_seen"] is None or seen > a["last_seen"]
            ):
                a["last_seen"] = seen

    if with_false:
        false_records = list(false_for(path)) + [
            r for _, _, p in extra for r in false_for(p)
        ]
        for r in false_records:
            if not r.get("type") or r.get("data") is None:
                continue
            a = asset(r["type"], str(r["data"]))
            if a["status"] is None:
                a["status"] = "false"
            module = r.get("module")
            if module:
                a["sources"].add(module)
            reason = r.get("reason") or "descendant of a false finding"
            entry = {
                "module": module,
                "reason": reason,
                "hidden": bool(r.get("hidden")),
            }
            if (
                entry not in a["false_reasons"]
                and len(a["false_reasons"]) < MAX_CONTEXTS
            ):
                a["false_reasons"].append(entry)

    out = []
    for a in by_key.values():
        tags = a["tags"]
        if "in-scope" in tags:
            # a name that entered scope later (a domain promoted by related_domains) is not a third party
            tags.discard("third-party")
        out.append(
            {
                "type": a["type"],
                "data": a["data"],
                "sources": sorted(a["sources"]),
                "tags": sorted(tags),
                "last_seen": a["last_seen"],
                "scan_date": scan_date,
                "status": a["status"],
                "details": a["details"],
                "contexts": list(a["contexts"].values()),
                "false_reasons": a["false_reasons"],
                "hosts": sorted(a["hosts"]),
                "ports": sorted(a["ports"]),
                "on": [
                    {"host": h, "ports": sorted(p)} for h, p in sorted(a["on"].items())
                ],
                "via": sorted(a["via"] or ()),
                "enriched_by": sorted(a["enriched_by"]),
                "screenshots": list(a["screenshots"].values()),
                "registrable": is_registrable(a["type"], a["data"]),
                # HTTP status codes of a URL (http's status-NNN tags; several when the answer changed between paths)
                # (a screenshot: the code the browser got, after redirects)
                "http_status": sorted(
                    {
                        int(t[7:])
                        for t in tags
                        if t.startswith("status-") and t[7:].isdigit()
                    }
                    | a["codes"]
                ),
            }
        )
    out.sort(key=lambda a: (-len(a["sources"]), a["type"], a["data"]))
    return out


# ---------- discovery chain ----------

MAX_CHAINS = 20


def _freshness(e):
    return next(
        (
            t[len("freshness-") :]
            for t in e.get("tags") or []
            if t.startswith("freshness-")
        ),
        None,
    )


def _chain_of(e, by_uuid, status):
    """Seed -> ... -> e, one step per parent_chain uuid; steps not in the output (omitted types) keep only
    their type and the discovery text."""
    uuids = e.get("parent_chain") or [e.get("uuid")]
    texts = e.get("discovery_path") or []
    steps = []
    for i, u in enumerate(uuids):
        ev = by_uuid.get(u)
        text = texts[i] if i < len(texts) else ""
        if ev is None:
            steps.append({"type": str(u).split(":", 1)[0], "data": None, "module": None, "context": text[:500],
                          "status": None, "freshness": None, "in_output": False})  # fmt: skip
            continue
        steps.append(
            {
                "type": ev.get("type"),
                "data": asset_data(ev),
                # raw module: "A" / "MX" (a DNS record of live resolution) and "SEED" say more than "dnsresolve"
                "module": ev.get("module"),
                "context": (ev.get("discovery_context") or text)[:500],
                "status": status.get(ev.get("id")),
                "freshness": _freshness(ev),
                "in_output": True,
            }
        )
    return steps


def _chains_in(events, false_records, etype, data):
    """Chains of one finding inside one scan's output (+ its false records)."""
    status = compute_status(events)
    by_uuid = {e.get("uuid"): e for e in events if e.get("uuid")}
    by_id = defaultdict(list)
    for e in events:
        by_id[e.get("id")].append(e)
    chains = []
    for e in events:
        if e.get("type") == etype and asset_data(e) == data:
            chains.append({"steps": _chain_of(e, by_uuid, status)})
    for r in false_records:
        if r.get("type") != etype or str(r.get("data")) != data:
            continue
        parents = by_id.get(r.get("parent")) or []
        base = _chain_of(parents[0], by_uuid, status) if parents else []
        last = {"type": etype, "data": data, "module": r.get("module"), "context": "", "status": "false",
                "freshness": None, "in_output": False}  # fmt: skip
        chains.append({"steps": base + [last], "false_reason": r.get("reason") or "descendant of a false finding",
                       "hidden": bool(r.get("hidden"))})  # fmt: skip
    return chains


def discovery_chains(path, etype, data, include_enrichments=True):
    """Every distinct way a finding was discovered: [{"steps": [...], "false_reason"?}], shortest first.

    A finding seen several times (other sources, other parents) has several chains. A false finding is not in the
    output: its chain is the parent's chain plus a last step with the reason it was dropped or hidden.
    A finding of an enrichment scan continues the shortest chain of its seed in the original scan; the steps made by
    the enrichment carry "scan": <enrichment scan name>."""
    events = events_for(path)
    false_records = list(false_for(path))
    found = _chains_in(events, false_records, etype, data)
    if include_enrichments:
        base_cache = {}

        def base_of(seed_type, seed_data):
            key = (seed_type, seed_data)
            if key not in base_cache:
                own = sorted(
                    _chains_in(events, false_records, *key),
                    key=lambda c: len(c["steps"]),
                )
                base_cache[key] = own[0]["steps"] if own else []
            return base_cache[key]

        for name, p in enrichment_outputs(path):
            for c in _chains_in(events_for(p), list(false_for(p)), etype, data):
                steps = [dict(st, scan=name) for st in c["steps"]]
                if (
                    steps
                    and steps[0]["module"] == "SEED"
                    and steps[0]["data"] is not None
                ):
                    base = base_of(steps[0]["type"], steps[0]["data"])
                    if base:
                        # the seed is the last step of its chain in the original scan
                        steps = base + steps[1:]
                found.append(dict(c, steps=steps))
    chains, seen = [], set()
    for c in found:
        key = tuple((st["type"], st["data"], st["module"]) for st in c["steps"])
        if key not in seen:
            seen.add(key)
            chains.append(c)
    chains.sort(key=lambda c: (len(c["steps"]), "false_reason" in c))
    total, chains = len(chains), chains[:MAX_CHAINS]
    return {
        "type": etype,
        "data": data,
        "total": total,
        "chains": chains,
        "graph": chains_graph(chains, etype, data),
    }


STATUS_ORDER = {None: -1, "false": 0, "historical": 1, "valid": 2}


def chains_graph(chains, etype, data):
    """The chains merged into one graph: a node per finding (type + value), an edge per "found from" relation.

    Steps that are not in the output (omitted types) become their own nodes, one per chain position, so unrelated
    omitted responses are not glued together. Node status = the best status of its steps; the edge keeps the modules
    that made the relation and a sample of the discovery text."""
    nodes, edges = {}, {}
    for ci, c in enumerate(chains):
        prev = None
        for si, st in enumerate(c["steps"]):
            if st["data"] is None:
                nid = f"omitted:{ci}:{si}"
            else:
                nid = f"{st['type']}\x00{st['data']}"
            n = nodes.get(nid)
            if n is None:
                n = nodes[nid] = {"id": nid, "type": st["type"], "data": st["data"], "status": st["status"],
                                  "in_output": st["in_output"], "seed": si == 0, "target": False}  # fmt: skip
            elif STATUS_ORDER.get(st["status"], -1) > STATUS_ORDER.get(n["status"], -1):
                n["status"] = st["status"]
            if st["type"] == etype and st["data"] == data:
                n["target"] = True
                if c.get("false_reason"):
                    n["false_reason"] = c["false_reason"]
                    n["hidden"] = c.get("hidden", False)
            if prev is not None and prev != nid:
                e = edges.setdefault(
                    (prev, nid),
                    {"from": prev, "to": nid, "modules": [], "context": st["context"]},
                )
                if st["module"] and st["module"] not in e["modules"]:
                    e["modules"].append(st["module"])
            prev = nid
    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


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


PROBLEM_LABELS = {
    "unavailable": "unavailable (no answer)",
    "rate_limit": "rate limited (HTTP 429)",
    "quota": "quota exhausted",
    "auth": "key refused (401/403)",
    "server_error": "server error (5xx)",
    "error": "failed requests",
}


def source_problems(stats, state, detail):
    """What went wrong with a source during the scan: failed requests by kind (with the last sample) and the
    module's own state (did not start / stopped after too many failures)."""
    out = []
    for kind, label in PROBLEM_LABELS.items():
        n = (stats.get("outcomes") or {}).get(kind)
        if n:
            out.append(
                {
                    "kind": kind,
                    "label": label,
                    "count": n,
                    "sample": (stats.get("errors") or {}).get(kind, ""),
                }
            )
    if state in ("failed", "error"):
        out.append({"kind": state, "label": "did not start" if state == "failed" else "stopped (error state)",
                    "count": None, "sample": detail})  # fmt: skip
    return out


def scan_report(name, producers=None):
    """What and how much each source of the scan found.

    producers - modules that emit data at all: loaded modules outside this set
    (report modules such as affiliates) are left out of the report when they found nothing."""
    d = safe_scan_dir(name)
    path = d / "output.json" if d else None
    if path is None or (not path.is_file() and not _imported(name)):
        return None
    events = events_for(path)
    status = compute_status(events)

    scan_info = {}
    per = defaultdict(
        lambda: {"events": 0, "assets": set(), "types": Counter(), "status": Counter()}
    )
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
    for r in false_for(path):
        false_by_module[source_name(r.get("module"))] += 1

    loaded, failed, errored = parse_console(_console_log(name))
    mstats = quota.module_stats(d)
    # internal/output modules make no API requests; sources with requests are in the report even without data
    requested = {m for m, st in mstats.items() if st.get("requests")}
    names = (
        set(per)
        | set(loaded)
        | set(failed)
        | set(errored)
        | set(false_by_module)
        | requested
    )
    sources = []
    for m in names:
        p = per.get(m)
        if (p is None and producers is not None and m not in producers and m not in failed and m not in errored
                and m not in requested):  # fmt: skip
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
        sources.append(
            {
                "name": m,
                "state": state,
                "detail": detail,
                "events": p["events"] if p else 0,
                "assets": assets,
                "only": only,
                "types": dict(p["types"].most_common()) if p else {},
                "status": dict(p["status"]) if p else {},
                "false": false_by_module.get(m, 0),
                "quota": quota.scan_quota(d, m),
                "problems": source_problems(mstats.get(m) or {}, state, detail),
            }
        )
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
        check = next(
            (t[len("dns-check-") :] for t in a["tags"] if t.startswith("dns-check-")),
            None,
        )
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
        "has_module_stats": bool(mstats),
        "problem_sources": sum(1 for s in sources if s["problems"]),
        "sources": sources,
    }


# ---------- starting scans ----------


class ScanError(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.code = code


# A bounded pool runs scans concurrently (TOKOSINT_MAX_SCANS, default 2); further requests queue.
# Each scan runs with its own BBoT home (DNS cache, temp) so parallel scans do not share mutable state;
# the heavy downloaded tools/lib (gowitness etc.) are symlinked from a shared base and fetched once.
MAX_CONCURRENT = max(1, int(os.environ.get("TOKOSINT_MAX_SCANS", "2") or "2"))
HOMES_DIR = SCANS_DIR / ".homes"
BBOT_BASE = Path(
    os.environ.get("TOKOSINT_BBOT_BASE", str(Path.home() / ".bbot"))
).expanduser()

_jobs = {}  # scan name -> job record (see _reserve); insertion order is the queue order
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
            out.append(
                str(ipaddress.ip_network(t, strict=False))
                if "/" in t
                else str(ipaddress.ip_address(t))
            )
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


def _scan_home(name):
    """An isolated BBoT working directory for one scan under scans/.homes/<name>.

    The large, read-only tools and lib (downloaded binaries such as gowitness, ~700 MB) are symlinked from the
    shared base (TOKOSINT_BBOT_BASE, default ~/.bbot) so they are not copied per scan; cache and temp are the
    scan's own, so concurrent scans never write the same cache. Falls back to the shared base if symlinking fails."""
    home = HOMES_DIR / name
    try:
        home.mkdir(parents=True, exist_ok=True)
        for sub in ("tools", "lib"):
            src = BBOT_BASE / sub
            if not src.is_dir():
                continue
            link = home / sub
            if not link.exists():
                link.symlink_to(src.resolve(), target_is_directory=True)
        return home
    except OSError:
        return BBOT_BASE


def _cleanup_home(name):
    """Remove a finished scan's working home (its output lives in scans/<name>, independent of the home).
    rmtree does not follow the tools/lib symlinks, so the shared base is untouched."""
    import shutil

    with contextlib.suppress(OSError):
        shutil.rmtree(HOMES_DIR / name, ignore_errors=True)


def _build_cmd(name, targets, modules, targets_file, seeds_file, config, home):
    cmd = [str(OSINT), "-t", *([str(targets_file)] if targets_file else targets), "-n", name, "-y", "--no-deps",
           "-c", "scope.report_distance=1", "-c", f"home={home}", *config]  # fmt: skip
    if seeds_file:
        cmd += ["-s", str(seeds_file)]
    cmd += ["-m", *modules] if modules else ["-f", "passive"]
    return cmd


# ---- pool state (helpers assume the caller holds _lock unless noted) ----

_ACTIVE = ("launching", "running")


def _active_count():
    return sum(1 for j in _jobs.values() if j["state"] in _ACTIVE)


def _queued_names():
    return [n for n, j in _jobs.items() if j["state"] == "queued"]


def has_capacity():
    """True if a new scan can start right now without queueing."""
    with _lock:
        return _active_count() < MAX_CONCURRENT


def running_jobs():
    """Names of scans whose process is currently running."""
    with _lock:
        out = []
        for name, j in _jobs.items():
            proc = j.get("proc")
            if j["state"] in _ACTIVE and (proc is None or proc.poll() is None):
                out.append(name)
    return out


def running_job():
    """The name of one running scan, or None. Kept for callers that only need to know if anything is running."""
    names = running_jobs()
    return names[0] if names else None


def queued_jobs():
    with _lock:
        return _queued_names()


def start_scan(
    payload,
    known_sources,
    on_finish=None,
    meta=None,
    targets_file=None,
    seeds_file=None,
    config=(),
):
    """Validate a scan request, reserve its name and either launch it or queue it (see the pool note above).

    payload: {targets, name?, modules?: [...]} - empty modules = the whole passive set.
    on_finish(name, returncode) is called from a watcher thread when the BBoT process exits;
    meta (e.g. company/schedule ids) is kept with the job and shown in job_info.
    targets_file / seeds_file - BBoT reads targets (scope) / seeds (what modules start from) from these files
    (enrichment of a finished scan, web/enrich.py); config - extra "key=value" BBoT options.
    Returns job_info(name); a queued scan has state "queued" and starts when a slot frees."""
    targets = (
        parse_targets(payload.get("targets"))
        if targets_file is None
        else list(payload.get("targets") or [])
    )
    name = str(payload.get("name") or "").strip().lower() or default_name(targets)
    if not NAME_RE.match(name):
        raise ScanError(
            "scan name: lowercase latin letters, digits, _ and -, up to 60 characters"
        )
    modules = payload.get("modules") or []
    if not isinstance(modules, list) or any(m not in known_sources for m in modules):
        raise ScanError("unknown source in the module list")

    with _lock:
        if (SCANS_DIR / name).exists() or name in _jobs:
            raise ScanError(f"scan {name} already exists, choose another name", 409)
        SCANS_DIR.mkdir(exist_ok=True)
        _jobs[name] = {
            "state": "queued",
            "targets": targets,
            "modules": modules,
            "meta": dict(meta or {}),
            "on_finish": on_finish,
            "started": time.time(),
            "proc": None,
            "returncode": None,
            "stopping": False,
            "log": SCANS_DIR / f"{name}.console.log",
            "cmd_args": (
                name,
                targets,
                modules,
                targets_file,
                seeds_file,
                list(config),
            ),
        }
    _dispatch()
    return job_info(name)


def _dispatch():
    """Launch queued scans while the pool has free slots. Safe to call from several watcher threads."""
    while True:
        with _lock:
            if _active_count() >= MAX_CONCURRENT:
                return
            name = next(iter(_queued_names()), None)
            if name is None:
                return
            _jobs[name]["state"] = (
                "launching"  # reserve the slot before we release the lock
            )
        try:
            _launch(name)
        except Exception as e:  # noqa: BLE001 - a failed launch must not wedge the queue
            import sys

            with _lock:
                j = _jobs.get(name)
                if j is not None:
                    j["state"], j["returncode"] = "done", -1
            sys.stderr.write(f"  failed to launch scan {name}: {e}\n")


def _launch(name):
    j = _jobs[name]
    cmd_name, targets, modules, targets_file, seeds_file, config = j["cmd_args"]
    home = _scan_home(cmd_name)
    cmd = _build_cmd(cmd_name, targets, modules, targets_file, seeds_file, config, home)
    # quota of the sources' accounts right before the scan (account endpoints spend no quota); written next to
    # the scan's output when it ends, together with the snapshot after it
    quota_before = quota.snapshot(modules or None)
    with open(j["log"], "w", encoding="utf-8") as log:
        # preexec_fn only resets a signal handler - no locks, safe with the server's threads
        proc = subprocess.Popen(
            cmd,
            cwd=str(ROOT),
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env=_child_env(),
            preexec_fn=_restore_sigint,  # noqa: PLW1509
        )
    with _lock:
        j["proc"] = proc
        j["state"] = "running"
        j["started_run"] = time.time()
    threading.Thread(
        target=_watch,
        args=(name, proc, j["on_finish"], modules, quota_before),
        daemon=True,
    ).start()


def _watch(name, proc, on_finish, modules=None, quota_before=None):
    rc = proc.wait()
    scan_dir = SCANS_DIR / name
    if scan_dir.is_dir():
        with contextlib.suppress(OSError):
            (scan_dir / "quota_before.json").write_text(
                json.dumps(quota_before or {}, indent=1)
            )
        quota.save_snapshot(scan_dir, "after", modules or None)
    with _lock:
        j = _jobs.get(name)
        if j is not None:
            j["state"], j["returncode"] = "done", rc
    _cleanup_home(name)
    _dispatch()  # a slot is free: start the next queued scan
    _import_to_db(
        name
    )  # the database becomes the source of truth; the output.json can then be deleted
    if on_finish is None:
        return
    try:
        on_finish(name, rc)
    except Exception as e:  # noqa: BLE001 - post-processing must never kill the server
        import sys

        sys.stderr.write(f"  post-processing of scan {name} failed: {e}\n")


def _import_to_db(name):
    """Best-effort import of a finished scan's events into the database. A failure just leaves the files as the
    source (events_for falls back to them), so it never breaks a scan."""
    scan_dir = SCANS_DIR / name
    if not (scan_dir / "output.json").is_file():
        return
    try:
        import eventdb

        eventdb.import_scan(name, replace=True)
    except Exception as e:  # noqa: BLE001
        import sys

        sys.stderr.write(f"  importing scan {name} into the database failed: {e}\n")
    cache_findings(name)


def cache_findings(name):
    """Cache the scan's risk-bearing findings in the database for the cross-company Findings view (best-effort).

    Only findings that carry a risk level are stored (login pages, exposed ports/services, vulnerabilities, leaks -
    not the plain valid inventory). Enrichments are their own linked scans and are cached separately, so this
    aggregates the scan alone (include_enrichments=False) and the Findings view unions across a company's scans."""
    import eventdb
    import risk

    path = safe_scan_path(name)
    if path is None:
        return
    try:
        findings = risk.annotate(
            aggregate_scan(path, with_false=False, include_enrichments=False)
        )
        eventdb.store_findings(name, [f for f in findings if f.get("risk")])
    except Exception as e:  # noqa: BLE001
        import sys

        sys.stderr.write(f"  caching findings of scan {name} failed: {e}\n")


def _tail(path, n=12):
    try:
        with open(path, "rb") as fh:
            fh.seek(0, 2)
            fh.seek(max(0, fh.tell() - 8000))
            text = fh.read().decode("utf-8", errors="replace")
    except OSError:
        return []
    return [ANSI_RE.sub("", x) for x in text.splitlines()[-n:]]


def _queue_position(name):
    q = _queued_names()
    return q.index(name) + 1 if name in q else None


def job_info(name):
    with _lock:
        j = _jobs.get(name)
        if j is None:
            return None
        proc = j.get("proc")
        rc = proc.poll() if proc is not None else None
        state = j["state"]
        pos = _queue_position(name) if state == "queued" else None
        log = j.get("log")
        info = {
            "name": name,
            "targets": j["targets"],
            "modules": j["modules"],
            "started": j["started"],
            "running": state in _ACTIVE and rc is None,
            "state": state,
            "queued": state == "queued",
            "queue_position": pos,
            "returncode": j.get("returncode")
            if j.get("returncode") is not None
            else rc,
            "stopping": j.get("stopping", False),
            "meta": j.get("meta", {}),
        }
    info["log"] = _tail(log) if log is not None and Path(log).exists() else []
    return info


def list_jobs():
    """All jobs this process knows about, newest first (running, queued, finished)."""
    with _lock:
        names = sorted(_jobs, key=lambda n: _jobs[n]["started"], reverse=True)
    return [job_info(n) for n in names]


def pool_status():
    """Pool capacity and queue, for the UI and MCP."""
    with _lock:
        active, queued = _active_count(), len(_queued_names())
    return {"max_concurrent": MAX_CONCURRENT, "running": active, "queued": queued}


def stop_scan(name):
    """Stop a running scan (SIGINT - BBoT writes its output) or drop a queued one before it starts."""
    with _lock:
        j = _jobs.get(name)
        if j is None:
            raise ScanError("scan is not running", 404)
        if j["state"] == "queued":
            j["state"], j["returncode"] = "cancelled", -1
            proc = None
        else:
            proc = j.get("proc")
            if j["state"] not in _ACTIVE or proc is None or proc.poll() is not None:
                raise ScanError("scan is not running", 404)
            j["stopping"] = True
    if proc is None:  # a queued scan was dropped before it started
        return job_info(name)
    # on Ctrl+C BBoT finishes the scan cleanly and writes its output
    os.killpg(proc.pid, signal.SIGINT)
    threading.Thread(target=_ensure_stopped, args=(proc,), daemon=True).start()
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
            if not d.is_dir() or d.name.startswith("."):
                continue
            out = d / "output.json"
            on_disk = out.is_file()
            if not on_disk and not _imported(d.name):
                continue  # a scan folder with neither its output.json nor an import (e.g. a work directory)
            if on_disk:
                try:
                    with open(out, encoding="utf-8") as fh:
                        events = sum(1 for _ in fh)
                except OSError:
                    events = 0
                mtime = int(out.stat().st_mtime)
            else:
                # the output.json was deleted after import: events live in the database
                import eventdb

                events = eventdb.event_count(d.name) or 0
                mtime = int(d.stat().st_mtime)
            started, targets = scan_head(out)
            try:
                enrich_of = json.loads((d / "enrich.json").read_text()).get("parent")
            except (OSError, ValueError):
                enrich_of = None
            scans.append({"name": d.name, "events": events, "mtime": mtime, "imported": not on_disk,
                          "started_at": started, "targets": targets, "enrich_of": enrich_of})  # fmt: skip
    running = set(running_jobs())
    for s in scans:
        s["running"] = s["name"] in running
    scans.sort(key=lambda s: s["mtime"], reverse=True)
    return scans
