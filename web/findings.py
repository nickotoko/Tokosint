"""Cross-company Findings view: risk-bearing findings (login pages, exposed ports/services, vulnerabilities,
leaks) across one or more companies, unioned over each company's scans and deduplicated by (type, value).

Built from the per-scan findings cache (eventdb.scan_findings, filled by scans.cache_findings), so it stays fast
even over huge scans. Manual status overrides are applied at query time - they can move a finding to historical or
drop it as false - so the view always reflects the latest analyst decisions without rebuilding the cache.

Only findings that carry a risk level are shown; the plain valid inventory (DNS names, IPs) is not a finding here.
"""

import eventdb
import risk
import store

# how "current" a status is when the same finding appears in several scans (valid wins over historical)
STATUS_RANK = {"valid": 2, "historical": 1, None: 0}
SNAPSHOT_FIELDS = (
    "sources",
    "hosts",
    "ports",
    "http_status",
    "tags",
    "screenshots",
    "details",
    "scans",
)


def _override_finding(f, override):
    """Apply a manual status override to a cached finding; returns the updated finding, or None if the override
    drops it from this view (false, or a downgrade that removes its risk)."""
    status = override["status"]
    if status == "false":
        return None
    g = dict(f)
    g["computed_status"] = f.get("status")
    g["status"] = status
    level, reasons, category = risk.assess(g)
    if not level:
        return None
    g["risk"], g["risk_reasons"], g["risk_category"] = level, reasons, category
    g["status_override"] = {
        "status": status,
        "note": override.get("note", ""),
        "at": override.get("at"),
    }
    return g


def _merge(into, f, scan):
    """Merge finding `f` (from `scan`) into the accumulated row `into` (same company + type + value)."""
    if into is None:
        row = {k: f.get(k) for k in ("type", "data", "risk", "risk_reasons", "risk_category", "status",
                                     "last_seen", "status_override")}  # fmt: skip
        row["sources"] = set(f.get("sources") or [])
        row["hosts"] = set(f.get("hosts") or [])
        row["ports"] = set(f.get("ports") or [])
        row["http_status"] = set(f.get("http_status") or [])
        row["tags"] = set(f.get("tags") or [])
        row["details"] = dict(f.get("details") or {})
        row["screenshots"] = list(f.get("screenshots") or [])
        row["scans"] = {scan}
        return row
    into["sources"] |= set(f.get("sources") or [])
    into["hosts"] |= set(f.get("hosts") or [])
    into["ports"] |= set(f.get("ports") or [])
    into["http_status"] |= set(f.get("http_status") or [])
    into["tags"] |= set(f.get("tags") or [])
    for k, v in (f.get("details") or {}).items():
        into["details"].setdefault(k, v)
    for s in f.get("screenshots") or []:
        if s not in into["screenshots"]:
            into["screenshots"].append(s)
    into["scans"].add(scan)
    # worst risk and most-current status win
    if risk.RANK.get(f.get("risk"), 0) > risk.RANK.get(into.get("risk"), 0):
        into["risk"], into["risk_reasons"] = f.get("risk"), f.get("risk_reasons")
        into["risk_category"] = f.get("risk_category")
    if STATUS_RANK.get(f.get("status"), 0) > STATUS_RANK.get(into.get("status"), 0):
        into["status"] = f.get("status")
        into["status_override"] = f.get("status_override")
    ls = f.get("last_seen")
    if isinstance(ls, (int, float)) and (
        into.get("last_seen") is None or ls > into["last_seen"]
    ):
        into["last_seen"] = ls
    return into


def _finalize(row, company_id, company):
    title = next((s.get("title") for s in row["screenshots"] if s.get("title")), None)
    return {
        "company": company,
        "company_id": company_id,
        "type": row["type"],
        "data": row["data"],
        "risk": row["risk"],
        "risk_reasons": row["risk_reasons"] or [],
        "category": row.get("risk_category"),
        "category_label": risk.CATEGORIES.get(
            row.get("risk_category"), row.get("risk_category")
        ),
        "status": row["status"],
        "status_override": row.get("status_override"),
        "sources": sorted(row["sources"]),
        "hosts": sorted(row["hosts"]),
        "ports": sorted(row["ports"]),
        "http_status": sorted(row["http_status"]),
        "title": title,
        "tags": sorted(row["tags"]),
        "details": row["details"],
        "last_seen": row.get("last_seen"),
        "screenshots": len(row["screenshots"]),
        "scans": sorted(row["scans"]),
    }


def company_findings(
    company_ids=None, status=None, risk_level=None, category=None, q=None
):
    """Risk-bearing findings across the given companies (all companies if none/empty), unioned over each company's
    scans and deduplicated per company by (type, value). `category` filters by the kind of finding (login / port /
    service / leak / vuln / exposure). Returns {findings, facets, total}."""
    companies = {c["id"]: c["name"] for c in store.list_companies()}
    ids = [int(i) for i in (company_ids or []) if int(i) in companies] or list(
        companies
    )

    scan_company, company_overrides = {}, {}
    for cid in ids:
        links = store.company_scans(cid)
        for link in links:
            scan_company[link["scan"]] = cid
        # one call returns every override in effect for the company (keyed by (type, data))
        company_overrides[cid] = (
            store.overrides_for_scan(links[0]["scan"]) if links else {}
        )

    acc = {}
    for scan, f in eventdb.findings_for_scans(scan_company):
        cid = scan_company.get(scan)
        if cid is None:
            continue
        o = company_overrides.get(cid, {}).get((f["type"], str(f["data"])))
        if o is not None:
            f = _override_finding(f, o)
            if f is None:
                continue
        key = (cid, f["type"], str(f["data"]))
        acc[key] = _merge(acc.get(key), f, scan)

    rows = [_finalize(acc[(cid, t, d)], cid, companies[cid]) for (cid, t, d) in acc]

    # facets over the unfiltered set, so the filter controls can show every available option and its count
    comp = {}
    for r in rows:
        key = (r["company_id"], r["company"])
        comp[key] = comp.get(key, 0) + 1
    facets = {
        "companies": [
            {"id": cid, "name": nm, "count": n}
            for (cid, nm), n in sorted(comp.items(), key=lambda x: x[0][1])
        ],
        "categories": [
            {"value": v, "count": c, "label": risk.CATEGORIES.get(v, v)}
            for v, c in sorted(_cat_counts(rows).items(), key=lambda x: -x[1])
        ],
        "risk": _counts((r["risk"] for r in rows), order=risk.LEVELS),
        "status": _counts(r["status"] for r in rows),
        "total": len(rows),
    }

    rl = (risk_level or "").strip().lower()
    st = (status or "").strip().lower()
    cat = (category or "").strip().lower()
    query = (q or "").strip().lower()
    out = [
        r for r in rows
        if (not rl or r["risk"] == rl)
        and (not st or (r["status"] or "") == st)
        and (not cat or (r["category"] or "") == cat)
        and (not query or query in str(r["data"]).lower())
    ]  # fmt: skip
    out.sort(
        key=lambda r: (
            -risk.RANK.get(r["risk"], 0),
            r["company"],
            r["type"],
            str(r["data"]),
        )
    )
    return {"findings": out, "facets": facets, "total": len(out)}


def _cat_counts(rows):
    c = {}
    for r in rows:
        v = r.get("category")
        if v:
            c[v] = c.get(v, 0) + 1
    return c


def _counts(values, order=None):
    c = {}
    for v in values:
        if v is None:
            continue
        c[v] = c.get(v, 0) + 1
    if order:
        return [{"value": v, "count": c[v]} for v in order if v in c]
    return [{"value": v, "count": c[v]} for v in sorted(c)]


# ---------- company assets (the Scans "Analysis" view, but for a whole company) ----------
# Same aggregated findings as /api/scan/<name>, unioned over all of a company's scans and deduplicated by
# (type, value). Everything is shown (not only risk), so the Assets tab mirrors the scan view at company scope.

_ASSET_SETS = ("sources", "tags", "hosts", "ports", "http_status", "enriched_by")
_STATUS_ORDER = {None: -1, "false": 0, "historical": 1, "valid": 2}


def company_assets(company_id):
    """All assets of a company: aggregate each of its scans and merge by (type, value). Overrides and risk are
    applied to the merged result, so it matches the per-scan Analysis view. On-demand (no cache): heavy on very
    large scans, like the scan view itself."""
    import overrides

    import scans

    store.get_company(company_id)  # validates / 404
    links = store.company_scans(company_id)
    acc = {}
    for link in links:
        path = scans.safe_scan_path(link["scan"])
        if path is None:
            continue
        for f in scans.aggregate_scan(path, include_enrichments=False):
            key = (f["type"], str(f["data"]))
            a = acc.get(key)
            if a is None:
                a = {"type": f["type"], "data": f["data"], "status": f.get("status"),
                     "last_seen": f.get("last_seen"), "scan_date": f.get("scan_date"),
                     "registrable": f.get("registrable", False), "details": {}, "contexts": [],
                     "false_reasons": [], "on": {}, "via": set(), "screenshots": {}, "scans": set()}  # fmt: skip
                for s in _ASSET_SETS:
                    a[s] = set()
                acc[key] = a
            for s in _ASSET_SETS:
                a[s] |= set(f.get(s) or [])
            a["via"] |= set(f.get("via") or [])
            a["scans"].add(link["scan"])
            for k, v in (f.get("details") or {}).items():
                a["details"].setdefault(k, v)
            for ctx in f.get("contexts") or []:
                if ctx not in a["contexts"]:
                    a["contexts"].append(ctx)
            for fr in f.get("false_reasons") or []:
                if fr not in a["false_reasons"]:
                    a["false_reasons"].append(fr)
            for item in f.get("on") or []:
                a["on"].setdefault(item["host"], set()).update(item.get("ports") or [])
            for sh in f.get("screenshots") or []:
                a["screenshots"].setdefault(sh.get("path"), sh)
            if _STATUS_ORDER.get(f.get("status"), -1) > _STATUS_ORDER.get(
                a["status"], -1
            ):
                a["status"] = f.get("status")
            ls = f.get("last_seen")
            if isinstance(ls, (int, float)) and (
                a["last_seen"] is None or ls > a["last_seen"]
            ):
                a["last_seen"] = ls

    rows = []
    for a in acc.values():
        rows.append({
            "type": a["type"], "data": a["data"], "status": a["status"], "last_seen": a["last_seen"],
            "scan_date": a["scan_date"], "registrable": a["registrable"],
            "sources": sorted(a["sources"]), "tags": sorted(a["tags"]), "hosts": sorted(a["hosts"]),
            "ports": sorted(a["ports"]), "http_status": sorted(a["http_status"]),
            "enriched_by": sorted(a["enriched_by"]), "details": a["details"], "contexts": a["contexts"],
            "false_reasons": a["false_reasons"], "via": sorted(a["via"]), "scans": sorted(a["scans"]),
            "on": [{"host": h, "ports": sorted(p)} for h, p in sorted(a["on"].items())],
            "screenshots": list(a["screenshots"].values()),
        })  # fmt: skip
    # one override log covers the whole company; apply it, then risk
    if links:
        overrides.apply(links[0]["scan"], rows)
    risk.annotate(rows)
    rows.sort(key=lambda r: (-len(r["sources"]), r["type"], str(r["data"])))
    return rows
