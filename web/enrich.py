"""Enrichment of a finished scan: run new sources over the findings it already has.

A connected source (a new key, a new module) normally sees only new scans. Enrichment starts a BBoT scan that
- keeps the scope of the original: its targets plus the domains related_domains promoted into scope (-t);
- starts from its findings (-s seeds) of the event types the chosen sources consume: valid and historical
  findings only, without third-party infrastructure (provider names and fronts) and false ones;
- keeps their status: validity reads seed_status.json, so a historical finding stays historical and so does
  what the new source finds on it.

The result is an ordinary scan in scans/<parent>-enrich-<time>/ with enrich.json {parent, modules, seeds}. The web
view of the parent shows it merged with its enrichments (scans.aggregate_scan(..., include_enrichments)), and the
discovery chain of an enriched finding continues the chain of the seed in the parent. A scan of a company is linked to
the same company: its new findings get to the timeline and alerts like any other scan.
"""

import ipaddress
import json
import time
from collections import Counter

import scans
import store

ENRICH_META = "enrich.json"
# seeds / targets / seed statuses of an enrichment: scans/.enrich/<name>/ (no output.json, not a scan)
WORK_SUBDIR = ".enrich"
# finding types that can be a BBoT seed (string data); TECHNOLOGY, FINDING... are dicts and are never seeds
SEED_TYPES = ("DNS_NAME", "IP_ADDRESS", "IP_RANGE", "OPEN_TCP_PORT", "URL", "EMAIL_ADDRESS", "ASN", "ORG_STUB")
MAX_SEEDS = 5000


class EnrichError(store.StoreError):
    pass


def meta_of(name):
    """enrich.json of a scan (None - not an enrichment)."""
    d = scans.safe_scan_dir(name)
    if d is None:
        return None
    try:
        return json.loads((d / ENRICH_META).read_text())
    except (OSError, ValueError):
        return None


def root_of(name):
    """The original scan an enrichment belongs to (enrichments of an enrichment attach to the same original)."""
    seen = set()
    while name not in seen:
        seen.add(name)
        m = meta_of(name)
        if not m or not m.get("parent"):
            return name
        name = m["parent"]
    return name


def children(parent):
    """Names of the finished enrichments of a scan, oldest first."""
    out = []
    if not scans.SCANS_DIR.is_dir():
        return out
    for d in scans.SCANS_DIR.iterdir():
        if not (d / ENRICH_META).is_file() or not (d / "output.json").is_file():
            continue
        m = meta_of(d.name) or {}
        if m.get("parent") == parent:
            out.append((m.get("created") or 0, d.name))
    return [n for _, n in sorted(out)]


def consumed_types(modules, preloaded):
    types = set()
    for m in modules:
        types.update(e for e in (preloaded.get(m) or {}).get("watched_events", []) if e != "*")
    return types


def plan(parent, modules, preloaded):
    """What an enrichment of `parent` with `modules` would send: targets, seeds and their statuses."""
    parent = root_of(parent)
    path = scans.safe_scan_path(parent)
    if path is None:
        raise EnrichError("scan not found", 404)
    if not modules:
        raise EnrichError("choose at least one source")
    unknown = [m for m in modules if m not in preloaded]
    if unknown:
        raise EnrichError(f"unknown source: {', '.join(unknown)}")
    wanted = consumed_types(modules, preloaded) & set(SEED_TYPES)
    findings = scans.aggregate_scan(path, with_false=False, include_enrichments=True)
    _, targets = scans.scan_head(path)
    promoted = sorted({f["data"] for f in findings if f["type"] == "DNS_NAME" and "related_domains" in f["sources"]})
    seeds, status = [], {}
    for f in findings:
        if f["type"] not in wanted or f.get("status") not in ("valid", "historical"):
            continue
        if "third-party" in (f.get("tags") or []):
            continue
        data = str(f["data"])
        if "#" in data or "\n" in data:
            # BBoT strips "#" comments from seed files
            continue
        seeds.append(f)
        status[data] = f["status"]
    seeds.sort(key=lambda f: (f["status"] != "valid", f["type"], f["data"]))
    truncated = max(0, len(seeds) - MAX_SEEDS)
    seeds = seeds[:MAX_SEEDS]
    # addresses that were in scope in the original scan (resolved from its names): the enrichment's scope has only
    # the target names, so a seed on a bare IP (http://1.2.3.4/) would otherwise be out of scope and dropped
    in_scope_ips = sorted({h for f in seeds if "in-scope" in (f.get("tags") or []) for h in f.get("hosts") or []
                           if _is_ip(h)})  # fmt: skip
    return {
        "parent": parent,
        "modules": list(modules),
        "targets": sorted(set(targets) | set(promoted)) + [ip for ip in in_scope_ips if ip not in targets],
        "seeds": [f["data"] for f in seeds],
        "seed_status": {f["data"]: status[f["data"]] for f in seeds},
        "by_type": dict(Counter(f["type"] for f in seeds)),
        "by_status": dict(Counter(f["status"] for f in seeds)),
        "consumes": sorted(consumed_types(modules, preloaded)),
        "truncated": truncated,
    }


def _is_ip(host):
    try:
        ipaddress.ip_address(str(host).strip("[]"))
        return True
    except ValueError:
        return False


def summary(p):
    """The plan without the seed lists (for the UI)."""
    return {k: v for k, v in p.items() if k not in ("seeds", "seed_status")} | {"seed_count": len(p["seeds"])}


def start(parent, modules, preloaded, known_sources, on_finish=None):
    p = plan(parent, modules, preloaded)
    if not p["seeds"]:
        raise EnrichError("nothing to enrich: the scan has no findings of the types these sources take "
                          f"({', '.join(p['consumes']) or '-'})")  # fmt: skip
    name = f"{p['parent'][:40]}-enrich-{time.strftime('%Y%m%d_%H%M%S')}"
    work = scans.SCANS_DIR / WORK_SUBDIR / name
    work.mkdir(parents=True, exist_ok=True)
    (work / "targets.txt").write_text("\n".join(p["targets"]) + "\n")
    (work / "seeds.txt").write_text("\n".join(p["seeds"]) + "\n")
    (work / "seed_status.json").write_text(json.dumps(p["seed_status"]))
    meta = {"parent": p["parent"], "modules": p["modules"], "seeds": len(p["seeds"]), "by_type": p["by_type"],
            "created": time.time()}  # fmt: skip
    link = store.scan_link(p["parent"])

    def finished(scan, returncode):
        d = scans.SCANS_DIR / scan
        if d.is_dir():
            (d / ENRICH_META).write_text(json.dumps(meta, indent=1))
        if on_finish is not None:
            on_finish(scan, returncode)

    job = scans.start_scan(
        {"targets": p["targets"], "name": name, "modules": p["modules"]},
        known_sources,
        on_finish=finished,
        meta={"enrich_of": p["parent"], **({"company_id": link["company_id"]} if link else {})},
        targets_file=work / "targets.txt",
        seeds_file=work / "seeds.txt",
        config=[f"modules.validity.seed_status_file={work / 'seed_status.json'}"],
    )
    if link:
        store.link_scan(job["name"], link["company_id"], None, job["started"])
    job["plan"] = summary(p)
    return job
