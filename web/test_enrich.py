"""Enrichment of a finished scan (web/enrich.py): `bbot/.venv/bin/pytest web/test_enrich.py -q`."""

import json

import pytest

import enrich
import scans
import store
from test_findings import chained, write_scan

PRELOADED = {
    "detectzestack": {"watched_events": ["DNS_NAME"], "produced_events": ["TECHNOLOGY"]},
    "fofa": {"watched_events": ["IP_ADDRESS", "DNS_NAME"], "produced_events": ["OPEN_TCP_PORT"]},
}
VALID = ["freshness-current", "validity-valid", "in-scope"]
HIST = ["freshness-historical", "validity-historical", "in-scope"]


@pytest.fixture(autouse=True)
def tmp_env(tmp_path, monkeypatch):
    scans_dir = tmp_path / "scans"
    scans_dir.mkdir()
    monkeypatch.setattr(scans, "SCANS_DIR", scans_dir)
    monkeypatch.setattr(store, "DB_PATH", tmp_path / "tokosint.db")
    store.init()
    return scans_dir


def parent_scan(root):
    seed = chained("D:seed", "DNS_NAME:u1", "DNS_NAME", "acme.example", "SEED", ["DNS_NAME:u1"], ["seed"], tags=VALID + ["seed"])
    www = chained("D:www", "DNS_NAME:u2", "DNS_NAME", "old.acme.example", "crt", ["DNS_NAME:u1", "DNS_NAME:u2"],
                  ["seed", "crt found old"], tags=HIST)  # fmt: skip
    ns = chained("D:ns", "DNS_NAME:u3", "DNS_NAME", "ns1.provider.example", "NS", ["DNS_NAME:u1", "DNS_NAME:u3"],
                 ["seed", "NS record"], tags=["freshness-current", "validity-valid", "third-party"])  # fmt: skip
    ip = chained("I:1", "IP_ADDRESS:u4", "IP_ADDRESS", "192.0.2.1", "A", ["DNS_NAME:u1", "IP_ADDRESS:u4"], ["seed", "A"],
                 tags=["freshness-current", "validity-valid"])  # fmt: skip
    return write_scan(root, "base", [seed, www, ns, ip])


def test_plan_takes_consumed_types_and_keeps_status(tmp_env):
    parent_scan(tmp_env)
    p = enrich.plan("base", ["detectzestack"], PRELOADED)
    # DNS names only (what the source consumes), no third-party provider name
    assert p["seeds"] == ["acme.example", "old.acme.example"]
    assert p["seed_status"] == {"acme.example": "valid", "old.acme.example": "historical"}
    assert p["targets"] == ["acme.example"]
    # fofa also takes IPs
    assert "192.0.2.1" in enrich.plan("base", ["fofa"], PRELOADED)["seeds"]
    with pytest.raises(enrich.EnrichError):
        enrich.plan("base", [], PRELOADED)
    with pytest.raises(enrich.EnrichError):
        enrich.plan("nope", ["fofa"], PRELOADED)


def test_start_passes_scope_seeds_and_statuses(tmp_env, monkeypatch):
    parent_scan(tmp_env)
    calls = {}

    def fake_start(payload, known, on_finish=None, meta=None, targets_file=None, seeds_file=None, config=()):
        calls.update(payload=payload, meta=meta, targets=targets_file, seeds=seeds_file, config=list(config),
                     on_finish=on_finish)  # fmt: skip
        return {"name": payload["name"], "started": 1.0}

    monkeypatch.setattr(scans, "start_scan", fake_start)
    job = enrich.start("base", ["detectzestack"], PRELOADED, {"detectzestack"})
    assert job["name"].startswith("base-enrich-") and job["plan"]["seed_count"] == 2
    assert calls["meta"]["enrich_of"] == "base"
    assert calls["seeds"].read_text().split() == ["acme.example", "old.acme.example"]
    assert calls["targets"].read_text().split() == ["acme.example"]
    status_file = calls["config"][0].split("=", 1)[1]
    assert json.loads(open(status_file).read())["old.acme.example"] == "historical"
    # when the scan ends, it is marked as an enrichment of the original
    (tmp_env / job["name"]).mkdir()
    calls["on_finish"](job["name"], 0)
    assert enrich.meta_of(job["name"])["parent"] == "base"


def test_merged_view_and_chain(tmp_env):
    parent_scan(tmp_env)
    # the enrichment: seeded with old.acme.example (historical there), a technology found on it
    seed = chained("D:www", "DNS_NAME:e1", "DNS_NAME", "old.acme.example", "SEED", ["DNS_NAME:e1"], ["seeded"],
                   tags=HIST + ["seed"])  # fmt: skip
    tech = chained("T:1", "TECHNOLOGY:e2", "TECHNOLOGY", None, "detectzestack", ["DNS_NAME:e1", "TECHNOLOGY:e2"],
                   ["seeded", "detectzestack found nginx"], tags=HIST)  # fmt: skip
    tech["data_json"] = {"host": "old.acme.example", "technology": "nginx"}
    d = write_scan(tmp_env, "base-enrich-1", [seed, tech])
    (d / "enrich.json").write_text(json.dumps({"parent": "base", "modules": ["detectzestack"], "created": 2}))

    assert enrich.children("base") == ["base-enrich-1"]
    assert enrich.root_of("base-enrich-1") == "base"
    plain = {(f["type"], f["data"]) for f in scans.aggregate_scan(tmp_env / "base" / "output.json")}
    assert ("TECHNOLOGY", "nginx") not in plain
    merged = {(f["type"], f["data"]): f for f in scans.aggregate_scan(tmp_env / "base" / "output.json", include_enrichments=True)}
    t = merged[("TECHNOLOGY", "nginx")]
    assert t["status"] == "historical" and t["enriched_by"] == ["base-enrich-1"] and t["sources"] == ["detectzestack"]
    # the seed is not counted again (no SEED source, no enriched_by on the original finding)
    assert merged[("DNS_NAME", "old.acme.example")]["enriched_by"] == []
    # the chain continues the seed's chain in the original scan
    c = scans.discovery_chains(tmp_env / "base" / "output.json", "TECHNOLOGY", "nginx")["chains"][0]["steps"]
    assert [s["data"] for s in c] == ["acme.example", "old.acme.example", "nginx"]
    assert c[-1]["scan"] == "base-enrich-1" and "scan" not in c[0]
    # scan list marks the enrichment
    assert {s["name"]: s["enrich_of"] for s in scans.list_scans()}["base-enrich-1"] == "base"
