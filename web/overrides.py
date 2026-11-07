"""Manual status changes of findings: applying them to a scan's findings and recording new ones.

The computed status (web/validity.py) is never overwritten in the data: a finding with a manual status keeps it in
`computed_status`, gets `status_override` (who/when/why) and the `status-manual` tag, so the UI and the timeline
use the analyst's decision while the log keeps both for improving the validation rules.
"""

import companies
import scans
import store

MANUAL_TAG = "status-manual"
SNAPSHOT_FIELDS = ("sources", "tags", "false_reasons", "details", "contexts", "hosts", "ports")


def apply(scan, findings):
    """Applies the overrides in effect for the scan to its aggregated findings (in place); returns findings."""
    current = store.overrides_for_scan(scan)
    if not current:
        return findings
    for f in findings:
        o = current.get((f["type"], f["data"]))
        if o is None:
            continue
        f["computed_status"] = f.get("status")
        f["status"] = o["status"]
        f["status_override"] = {"status": o["status"], "computed": o["computed_status"], "note": o["note"],
                                "at": o["at"], "scan": o["scan"]}  # fmt: skip
        f["tags"] = sorted(set(f.get("tags") or []) | {MANUAL_TAG})
    return findings


def set_status(payload):
    """payload: {scan, type, data, status: valid|historical|false|"" (revert), note?}.

    Records the change with a snapshot of the evidence; if the scan belongs to a company, its registry and timeline
    are rebuilt (no alerts) so the decision applies there too. Returns the stored change."""
    name = str(payload.get("scan") or "")
    path = scans.safe_scan_path(name)
    if path is None:
        raise store.StoreError("scan not found", 404)
    type_, data = str(payload.get("type") or ""), str(payload.get("data") or "")
    finding = next((f for f in scans.aggregate_scan(path) if f["type"] == type_ and f["data"] == data), None)
    if finding is None:
        raise store.StoreError("finding not found in the scan", 404)
    snapshot = {k: finding.get(k) for k in SNAPSHOT_FIELDS}
    change = store.add_override(name, type_, data, str(payload.get("status") or ""),
                                computed_status=finding.get("status") or "", note=payload.get("note") or "",
                                snapshot=snapshot)  # fmt: skip
    if change["company_id"]:
        companies.rebuild(change["company_id"])
    return change
