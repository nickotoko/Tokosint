"""Scan finding status (valid / historical / false) across all discovery paths.

During a scan the `validity` module tags every OBSERVATION (an event from a specific module):
  validity-<status>  - status along the path this observation came through;
  freshness-<level>  - the observation's own freshness relative to its parent in the output
                       (current / historical / inherit / verified).

One finding may arrive through several paths: first from an archive (historical), later from a
current source. BBoT modules take the first copy, so its descendants may have stayed historical
inside the scan. Here the status is recomputed over the graph of all observations:

  status(finding) = max over observations o: min(own(o), status(parent of o))

own: current -> valid, historical -> historical, inherit -> no cap (takes the parent's),
verified -> valid regardless of the parent (confirmed now, e.g. a target name resolves).
The scan root is valid. Values only grow, so iterating to a fixed point terminates.
False findings are not in the output (see the scan's validity_false.jsonl).
"""

FALSE, HISTORICAL, VALID, VERIFIED = 0, 1, 2, 3
NAMES = {FALSE: "false", HISTORICAL: "historical", VALID: "valid"}
# freshness-false: a false observation (a hidden candidate domain re-emitted by the core as a graph link)
OWN = {"freshness-current": VALID, "freshness-historical": HISTORICAL, "freshness-inherit": VALID,
       "freshness-verified": VERIFIED, "freshness-false": FALSE}
TAGGED = {"validity-valid": VALID, "validity-historical": HISTORICAL, "validity-false": FALSE}


def compute_status(events):
    """events - JSONL scan dicts. Returns {event id: "valid"|"historical"|"false"};
    events without tags (scans made before validity existed) are not in the result."""
    status = {}
    edges = []  # (id, parent_id, own, status from the scan)
    for e in events:
        eid = e.get("id")
        if not eid:
            continue
        if e.get("type") == "SCAN":
            status[eid] = VALID
            continue
        tags = e.get("tags") or []
        own = next((OWN[t] for t in tags if t in OWN), None)
        if own is None:
            continue
        tagged = next((TAGGED[t] for t in tags if t in TAGGED), None)
        edges.append((eid, e.get("parent"), own, tagged))

    ids = {eid for eid, _, _, _ in edges} | set(status)
    for eid, _parent, own, _tagged in edges:
        if own == VERIFIED:
            status[eid] = VALID
    # an observation whose parent is missing from the output keeps the status computed in the scan
    for eid, parent, _own, tagged in edges:
        if parent not in ids and tagged is not None:
            status[eid] = max(status.get(eid, FALSE), tagged)

    changed = True
    while changed:
        changed = False
        for eid, parent, own, _tagged in edges:
            if own == VERIFIED:
                continue
            ps = status.get(parent)
            if ps is None:
                continue
            cand = min(own, ps)
            if cand > status.get(eid, -1):
                status[eid] = cand
                changed = True

    return {eid: NAMES[s] for eid, s in status.items() if not eid.startswith("SCAN:")}
