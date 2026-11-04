"""Tests for the graph status recompute: `bbot/.venv/bin/pytest web/test_validity.py -q`."""

from validity import compute_status


def ev(eid, parent, fresh, status, etype="DNS_NAME"):
    return {"type": etype, "id": eid, "parent": parent, "tags": [f"freshness-{fresh}", f"validity-{status}"]}


SCAN = {"type": "SCAN", "id": "SCAN:1", "parent": "SCAN:1", "tags": []}


def test_historical_parent_caps_children():
    events = [
        SCAN,
        ev("D:seed", "SCAN:1", "current", "valid"),
        ev("D:old", "D:seed", "historical", "historical"),
        ev("IP:old", "D:old", "current", "historical", "IP_ADDRESS"),
        ev("U:old", "D:old", "inherit", "historical", "URL"),
    ]
    st = compute_status(events)
    assert st["D:seed"] == "valid"
    assert st["D:old"] == "historical"
    assert st["IP:old"] == "historical"
    assert st["U:old"] == "historical"


def test_entity_upgraded_by_second_path():
    # 'old' first came from an archive and its IP got historical; then the same name came from a current source
    events = [
        SCAN,
        ev("D:seed", "SCAN:1", "current", "valid"),
        ev("D:old", "D:seed", "historical", "historical"),
        ev("IP:old", "D:old", "current", "historical", "IP_ADDRESS"),
        ev("D:old", "D:seed", "current", "valid"),
    ]
    st = compute_status(events)
    assert st["D:old"] == "valid"
    # the child is recomputed through the parent's new path
    assert st["IP:old"] == "valid"


def test_missing_parent_uses_scan_status_and_untagged_ignored():
    events = [
        SCAN,
        ev("D:orphan", "D:gone", "current", "historical"),
        {"type": "DNS_NAME", "id": "D:legacy", "parent": "SCAN:1", "tags": []},
    ]
    st = compute_status(events)
    assert st["D:orphan"] == "historical"
    assert "D:legacy" not in st


def test_verified_ignores_historical_parent():
    events = [
        SCAN,
        ev("D:seed", "SCAN:1", "current", "valid"),
        ev("U:arch", "D:seed", "historical", "historical", "URL"),
        ev("D:sub", "U:arch", "verified", "valid"),
        ev("IP:sub", "D:sub", "current", "valid", "IP_ADDRESS"),
        ev("D:gone", "U:arch", "historical", "historical"),
    ]
    st = compute_status(events)
    assert st["U:arch"] == "historical"
    assert st["D:sub"] == "valid"
    assert st["IP:sub"] == "valid"
    assert st["D:gone"] == "historical"


def test_false_observation_and_its_children():
    events = [
        SCAN,
        ev("D:seed", "SCAN:1", "current", "valid"),
        ev("D:ext", "D:seed", "false", "false"),
        ev("IP:ext", "D:ext", "current", "false", "IP_ADDRESS"),
        # the same name was promoted later (related_domains): valid through the second path
        ev("D:rel", "D:seed", "false", "false"),
        ev("D:rel", "D:seed", "verified", "valid"),
    ]
    st = compute_status(events)
    assert st["D:ext"] == "false"
    assert st["IP:ext"] == "false"
    assert st["D:rel"] == "valid"
