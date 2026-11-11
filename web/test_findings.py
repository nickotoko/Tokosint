"""Tests of findings: technologies and ports as fields, the scan report's failed sources and quotas,
manual status changes: `bbot/.venv/bin/pytest web/test_findings.py -q`."""

import json

import pytest

import companies
import overrides
import quota
import scans
import store

TAGS = ["freshness-current", "validity-valid", "in-scope"]


def ev(eid, etype, data=None, data_json=None, parent="SCAN:1", module="shodan_idb", host=None, port=None, tags=TAGS):
    e = {"type": etype, "id": eid, "parent": parent, "module": module, "tags": list(tags), "timestamp": 1000}
    if data is not None:
        e["data"] = data
    if data_json is not None:
        e["data_json"] = data_json
    if host:
        e["host"] = host
    if port:
        e["port"] = port
    return e


SCAN = {"type": "SCAN", "id": "SCAN:1", "parent": "SCAN:1", "tags": [],
        "data_json": {"status": "FINISHED", "started_at": 1000, "target": {"seeds": ["acme.example"]}}}  # fmt: skip


def write_scan(root, name, events, module_stats=None, before=None, after=None):
    d = root / name
    d.mkdir(parents=True)
    (d / "output.json").write_text("\n".join(json.dumps(e) for e in [SCAN, *events]) + "\n")
    if module_stats is not None:
        (d / "module_stats.json").write_text(json.dumps(module_stats))
    if before is not None:
        (d / "quota_before.json").write_text(json.dumps(before))
    if after is not None:
        (d / "quota_after.json").write_text(json.dumps(after))
    return d


@pytest.fixture(autouse=True)
def tmp_env(tmp_path, monkeypatch):
    scans_dir = tmp_path / "scans"
    scans_dir.mkdir()
    monkeypatch.setattr(scans, "SCANS_DIR", scans_dir)
    monkeypatch.setattr(quota, "SCANS_DIR", scans_dir)
    monkeypatch.setattr(store, "DB_PATH", tmp_path / "tokosint.db")
    store.init()
    return scans_dir


BASE_EVENTS = [
    ev("D:1", "DNS_NAME", "www.acme.example", module="SEED", host="www.acme.example"),
    ev("P:1", "OPEN_TCP_PORT", "www.acme.example:443", parent="D:1", host="www.acme.example", port=443),
    ev("P:2", "OPEN_TCP_PORT", "www.acme.example:8443", parent="D:1", host="www.acme.example", port=8443),
    # the same technology on two hosts, one with the banner port, one without (InternetDB gives none)
    ev("T:1", "TECHNOLOGY", data_json={"host": "www.acme.example", "technology": "cpe:2.3:a:f5:nginx", "port": 443},
       parent="D:1", host="www.acme.example", port=443),
    ev("T:2", "TECHNOLOGY", data_json={"host": "api.acme.example", "technology": "cpe:2.3:a:f5:nginx"},
       parent="D:1", host="api.acme.example"),
    ev("U:1", "URL", "https://www.acme.example:8443/login", parent="D:1", module="http", host="www.acme.example", port=8443),
]  # fmt: skip


def test_technology_and_ports_are_fields(tmp_env):
    d = write_scan(tmp_env, "s1", BASE_EVENTS)
    found = {(f["type"], f["data"]): f for f in scans.aggregate_scan(d / "output.json")}
    # one finding per technology (not per host), with where it was seen
    tech = found[("TECHNOLOGY", "cpe:2.3:a:f5:nginx")]
    assert tech["on"] == [{"host": "api.acme.example", "ports": []}, {"host": "www.acme.example", "ports": [443]}]
    assert tech["ports"] == [443] and tech["hosts"] == ["api.acme.example", "www.acme.example"]
    assert not any(t == "TECHNOLOGY" and data == "www.acme.example" for t, data in found)
    assert found[("OPEN_TCP_PORT", "www.acme.example:8443")]["ports"] == [8443]
    assert found[("URL", "https://www.acme.example:8443/login")]["ports"] == [8443]
    assert found[("DNS_NAME", "www.acme.example")]["ports"] == []


def test_report_shows_failed_sources_and_quota(tmp_env):
    stats = {
        "shodan_idb": {"requests": 12, "outcomes": {"ok": 10, "rate_limit": 2}, "errors": {"rate_limit": "HTTP 429: slow down"}},
        "crtname": {"requests": 3, "outcomes": {"ok": 1, "quota": 2}, "errors": {"quota": "HTTP 402: daily limit"}},
        "virustotal": {"requests": 0, "outcomes": {}, "errors": {}},
    }
    shodan = lambda left: {"at": 1, "counters": [quota._counter("query credits", left, 100, "month")]}  # noqa: E731
    d = write_scan(tmp_env, "s1", BASE_EVENTS, module_stats=stats, before={"shodan": shodan(40)}, after={"shodan": shodan(37)})
    rep = {s["name"]: s for s in scans.scan_report("s1")["sources"]}

    sh = rep["shodan_idb"]
    assert sh["quota"]["requests"] == 12
    assert [(p["kind"], p["count"]) for p in sh["problems"]] == [("rate_limit", 2)]
    assert sh["problems"][0]["sample"] == "HTTP 429: slow down"
    counter = sh["quota"]["counters"][0]
    assert (counter["spent"], counter["remaining"], counter["limit"]) == (3, 37, 100)

    # no account endpoint: the documented free limit, minus the requests of scans in the window
    cn = rep["crtname"]
    assert cn["problems"][0]["label"] == "quota exhausted"
    assert cn["quota"]["free_limit"]["limit"] == 100 and cn["quota"]["free_limit"]["remaining_estimate"] == 97
    assert scans.scan_report("s1")["problem_sources"] == 2
    assert d.is_dir()


def test_quota_probe_errors_hide_the_key(monkeypatch):
    monkeypatch.setattr(quota, "_keys", lambda: {"hunterio": "SECRETKEY42"})

    def boom(key):
        raise ValueError(f"failed for {key}")

    monkeypatch.setitem(quota.PROBES, "hunterio", (boom, "hunterio", ["hunterio"]))
    snap = quota.snapshot(["hunterio", "fullhunt"])
    assert "SECRETKEY42" not in snap["hunterio"]["error"] and "***" in snap["hunterio"]["error"]
    assert "fullhunt" not in snap  # no key: not probed


def test_manual_status_scan_scope_and_log(tmp_env):
    write_scan(tmp_env, "s1", BASE_EVENTS)
    change = overrides.set_status({"scan": "s1", "type": "OPEN_TCP_PORT", "data": "www.acme.example:8443",
                                   "status": "false", "note": "port of a CDN"})  # fmt: skip
    assert change["computed_status"] == "valid" and change["company_id"] is None
    assert change["snapshot"]["sources"] == ["shodan_idb"] and change["snapshot"]["ports"] == [8443]

    found = {(f["type"], f["data"]): f for f in overrides.apply("s1", scans.aggregate_scan(tmp_env / "s1" / "output.json"))}
    port = found[("OPEN_TCP_PORT", "www.acme.example:8443")]
    assert port["status"] == "false" and port["computed_status"] == "valid"
    assert port["status_override"]["note"] == "port of a CDN" and "status-manual" in port["tags"]
    assert found[("OPEN_TCP_PORT", "www.acme.example:443")]["status"] == "valid"

    # revert: computed status again, but both changes stay in the log
    overrides.set_status({"scan": "s1", "type": "OPEN_TCP_PORT", "data": "www.acme.example:8443", "status": ""})
    found = {(f["type"], f["data"]): f for f in overrides.apply("s1", scans.aggregate_scan(tmp_env / "s1" / "output.json"))}
    assert "status_override" not in found[("OPEN_TCP_PORT", "www.acme.example:8443")]
    assert [c["status"] for c in store.override_log()] == ["", "false"]

    with pytest.raises(store.StoreError):
        overrides.set_status({"scan": "s1", "type": "DNS_NAME", "data": "www.acme.example", "status": "bogus"})
    with pytest.raises(store.StoreError):
        overrides.set_status({"scan": "s1", "type": "DNS_NAME", "data": "nope.acme.example", "status": "false"})


def test_manual_status_applies_to_company_timeline(tmp_env):
    write_scan(tmp_env, "s1", BASE_EVENTS)
    co = store.save_company({"name": "Acme", "targets": ["acme.example"]})
    companies.attach_scans(co["id"], ["s1"])
    has = lambda data: any(e["data"] == data for e in store.timeline(co["id"])["events"])  # noqa: E731
    assert has("www.acme.example:8443")

    overrides.set_status({"scan": "s1", "type": "OPEN_TCP_PORT", "data": "www.acme.example:8443", "status": "false"})
    assert not has("www.acme.example:8443"), "a finding marked false must leave the company timeline"

    # a later scan of the same company sees the decision too
    write_scan(tmp_env, "s2", BASE_EVENTS)
    store.link_scan("s2", co["id"])
    found = {f["data"]: f for f in overrides.apply("s2", scans.aggregate_scan(tmp_env / "s2" / "output.json"))}
    assert found["www.acme.example:8443"]["status"] == "false"


def test_registry_migration_runs_once(tmp_env, monkeypatch):
    co = store.save_company({"name": "Acme", "targets": []})
    rebuilt = []
    monkeypatch.setattr(companies, "rebuild", lambda cid: rebuilt.append(cid) or [])
    companies.migrate_registries()
    companies.migrate_registries()
    assert rebuilt == [co["id"]]


def chained(eid, uuid, etype, data, module, chain, texts, tags=TAGS):
    e = ev(eid, etype, data, module=module, tags=tags)
    e.update(uuid=uuid, parent_chain=chain, discovery_path=texts, discovery_context=texts[-1])
    return e


def test_discovery_chains(tmp_env):
    seed = chained("D:seed", "DNS_NAME:u1", "DNS_NAME", "acme.example", "SEED", ["DNS_NAME:u1"], ["seeded with acme.example"])
    sub = chained("D:www", "DNS_NAME:u2", "DNS_NAME", "www.acme.example", "crt", ["DNS_NAME:u1", "DNS_NAME:u2"], ["seed", "crt found www"],
                  tags=["freshness-historical", "validity-historical"])  # fmt: skip
    # an omitted step (HTTP_RESPONSE is not in the output) between the name and the email
    mail = chained("E:1", "EMAIL_ADDRESS:u4", "EMAIL_ADDRESS", "info@acme.example", "excavate", ["DNS_NAME:u1", "DNS_NAME:u2", "HTTP_RESPONSE:u3", "EMAIL_ADDRESS:u4"],
                   ["seed", "crt found www", "http got a response", "excavate found the email"])  # fmt: skip
    # the same email found a second way, straight from the seed
    mail2 = chained("E:1", "EMAIL_ADDRESS:u5", "EMAIL_ADDRESS", "info@acme.example", "hunterio", ["DNS_NAME:u1", "EMAIL_ADDRESS:u5"], ["seed", "hunter found it"])
    d = write_scan(tmp_env, "s1", [seed, sub, mail, mail2])
    (d / "validity_false.jsonl").write_text(json.dumps(
        {"type": "DNS_NAME", "data": "cdn.other.example", "module": "excavate", "parent": "D:www",
         "reason": "out-of-scope name without proven relation (excavate)", "hidden": True}) + "\n")  # fmt: skip

    r = scans.discovery_chains(d / "output.json", "EMAIL_ADDRESS", "info@acme.example")
    assert r["total"] == 2
    short, long_ = r["chains"]
    assert [s["module"] for s in short["steps"]] == ["SEED", "hunterio"]
    assert [s["type"] for s in long_["steps"]] == ["DNS_NAME", "DNS_NAME", "HTTP_RESPONSE", "EMAIL_ADDRESS"]
    omitted = long_["steps"][2]
    assert omitted["in_output"] is False and omitted["data"] is None and omitted["context"] == "http got a response"
    # each step carries the status of that finding: the historical name caps the path
    assert long_["steps"][1]["status"] == "historical" and long_["steps"][1]["freshness"] == "historical"

    # a false finding: the parent's chain plus the reason it was hidden
    f = scans.discovery_chains(d / "output.json", "DNS_NAME", "cdn.other.example")
    steps = f["chains"][0]["steps"]
    assert [s["data"] for s in steps] == ["acme.example", "www.acme.example", "cdn.other.example"]
    assert f["chains"][0]["hidden"] and "without proven relation" in f["chains"][0]["false_reason"]
    assert scans.discovery_chains(d / "output.json", "DNS_NAME", "nope.example")["chains"] == []


def test_discovery_graph_merges_chains(tmp_env):
    seed = chained("D:seed", "DNS_NAME:u1", "DNS_NAME", "acme.example", "SEED", ["DNS_NAME:u1"], ["seed"])
    www = chained("D:www", "DNS_NAME:u2", "DNS_NAME", "www.acme.example", "crt", ["DNS_NAME:u1", "DNS_NAME:u2"], ["s", "crt"])
    ip = chained("I:1", "IP_ADDRESS:u3", "IP_ADDRESS", "203.0.113.5", "A", ["DNS_NAME:u1", "DNS_NAME:u2", "IP_ADDRESS:u3"],
                 ["s", "crt", "A record of www"])  # fmt: skip
    # the same IP from the seed directly, and once more through itself (a loop)
    ip2 = chained("I:1", "IP_ADDRESS:u4", "IP_ADDRESS", "203.0.113.5", "robtex", ["DNS_NAME:u1", "IP_ADDRESS:u4"], ["s", "robtex"])
    www2 = chained("D:www", "DNS_NAME:u5", "DNS_NAME", "www.acme.example", "robtex",
                   ["DNS_NAME:u1", "IP_ADDRESS:u4", "DNS_NAME:u5"], ["s", "robtex", "robtex reverse"])  # fmt: skip
    d = write_scan(tmp_env, "s1", [seed, www, ip, ip2, www2])
    g = scans.discovery_chains(d / "output.json", "IP_ADDRESS", "203.0.113.5")["graph"]
    nodes = {n["data"]: n for n in g["nodes"]}
    assert set(nodes) == {"acme.example", "www.acme.example", "203.0.113.5"}  # merged, not one node per step
    assert nodes["acme.example"]["seed"] and nodes["203.0.113.5"]["target"]
    edges = {(e["from"].split("\x00")[1], e["to"].split("\x00")[1]): e["modules"] for e in g["edges"]}
    assert edges == {
        ("acme.example", "www.acme.example"): ["crt"],
        ("www.acme.example", "203.0.113.5"): ["A"],
        ("acme.example", "203.0.113.5"): ["robtex"],
    }


def test_findings_via_related_domain(tmp_env):
    seed = chained("D:seed", "DNS_NAME:u1", "DNS_NAME", "acme.example", "SEED", ["DNS_NAME:u1"], ["seed"])
    # related_domains promoted a subsidiary's domain into scope
    rel = chained("D:sub", "DNS_NAME:u2", "DNS_NAME", "subsidiary.example", "related_domains",
                  ["DNS_NAME:u1", "DNS_NAME:u2"], ["seed", "promoted"])  # fmt: skip
    www = chained("D:www", "DNS_NAME:u3", "DNS_NAME", "www.subsidiary.example", "crt",
                  ["DNS_NAME:u1", "DNS_NAME:u2", "DNS_NAME:u3"], ["seed", "promoted", "crt"])  # fmt: skip
    # an IP found both through the subsidiary and straight from the target: it is the target's own too
    ip1 = chained("I:1", "IP_ADDRESS:u4", "IP_ADDRESS", "192.0.2.1", "A",
                  ["DNS_NAME:u1", "DNS_NAME:u2", "DNS_NAME:u3", "IP_ADDRESS:u4"], ["seed", "promoted", "crt", "A"])  # fmt: skip
    ip2 = chained("I:1", "IP_ADDRESS:u5", "IP_ADDRESS", "192.0.2.1", "A", ["DNS_NAME:u1", "IP_ADDRESS:u5"], ["seed", "A"])
    d = write_scan(tmp_env, "s1", [seed, rel, www, ip1, ip2])
    via = {(f["type"], f["data"]): f["via"] for f in scans.aggregate_scan(d / "output.json")}
    assert via[("DNS_NAME", "acme.example")] == []
    assert via[("DNS_NAME", "subsidiary.example")] == ["subsidiary.example"]
    assert via[("DNS_NAME", "www.subsidiary.example")] == ["subsidiary.example"]
    assert via[("IP_ADDRESS", "192.0.2.1")] == []


def test_last_seen_is_the_source_date(tmp_env):
    # two sources: one gives a date, the other does not; the scan time is never a last_seen
    a = dict(ev("D:1", "DNS_NAME", "www.acme.example", module="robtex"), last_seen=1600000000.0, timestamp=1700000000)
    b = dict(ev("D:1", "DNS_NAME", "www.acme.example", module="crt"), timestamp=1700000005)
    c = dict(ev("D:2", "DNS_NAME", "api.acme.example", module="crt"), timestamp=1700000005)
    d = write_scan(tmp_env, "s1", [a, b, c])
    f = {x["data"]: x for x in scans.aggregate_scan(d / "output.json")}
    assert f["www.acme.example"]["last_seen"] == 1600000000.0
    assert f["api.acme.example"]["last_seen"] is None
    # the scan date: the scan's start time (SCAN event), the same for every finding
    assert f["www.acme.example"]["scan_date"] == 1000 and f["api.acme.example"]["scan_date"] == 1000
    assert "seen" not in f["www.acme.example"]


def test_last_seen_from_context_of_older_scans():
    assert scans.context_last_seen("robtex found X in Robtex passive DNS (A record of x, seen 2017-06-24 .. 2026-11-06)") == 1793923200.0
    assert scans.context_last_seen("shodan_idb ... (observed 2024-05-01)") == 1714521600.0
    assert scans.context_last_seen("netlas searched Netlas ... (seen 2024-05-01)") == 1714521600.0
    assert scans.context_last_seen("crt found www") is None and scans.context_last_seen(None) is None


def test_registrable_domains(tmp_env):
    names = ["acme.example", "www.acme.example", "acme.co.uk", "mail.acme.co.uk"]
    d = write_scan(tmp_env, "s1", [ev(f"D:{i}", "DNS_NAME", n, module="crt") for i, n in enumerate(names)]
                   + [ev("I:1", "IP_ADDRESS", "192.0.2.1", module="A")])  # fmt: skip
    reg = {f["data"]: f["registrable"] for f in scans.aggregate_scan(d / "output.json")}
    assert reg == {"acme.example": False, "www.acme.example": False, "acme.co.uk": True, "mail.acme.co.uk": False,
                   "192.0.2.1": False}  # fmt: skip


def test_url_http_status(tmp_env):
    url = ev("U:1", "URL", data_json={"url": "http://acme.example/", "redirect_location": "https://acme.example/"},
             module="http", tags=TAGS + ["status-301"])  # fmt: skip
    page = ev("U:2", "URL", data_json={"url": "https://acme.example/"}, module="http", tags=TAGS + ["status-200"])
    d = write_scan(tmp_env, "s1", [url, page])
    f = {x["data"]: x for x in scans.aggregate_scan(d / "output.json")}
    assert f["http://acme.example/"]["http_status"] == [301]
    assert f["http://acme.example/"]["details"]["redirect_location"] == "https://acme.example/"
    assert f["https://acme.example/"]["http_status"] == [200]


def test_screenshots_go_to_the_url_and_are_served_safely(tmp_env):
    shot = ev("W:1", "WEBSCREENSHOT", data_json={"path": "gowitness/screenshots/login.jpeg",
              "url": "https://www.acme.example:8443/login"}, parent="U:1", module="gowitness")  # fmt: skip
    d = write_scan(tmp_env, "s1", [*BASE_EVENTS, shot])
    (d / "gowitness" / "screenshots").mkdir(parents=True)
    (d / "gowitness" / "screenshots" / "login.jpeg").write_bytes(b"\xff\xd8\xff")
    (d / "output.json.bak").write_text("secret")
    found = {(f["type"], f["data"]): f for f in scans.aggregate_scan(d / "output.json")}
    want = [{"scan": "s1", "path": "gowitness/screenshots/login.jpeg", "url": "https://www.acme.example:8443/login",
             "status_code": None, "title": None, "requested_url": None, "status_reason": None, "redirect_chain": None}]
    assert found[("URL", "https://www.acme.example:8443/login")]["screenshots"] == want
    assert found[("DNS_NAME", "www.acme.example")]["screenshots"] == []
    # only images inside the scan's screenshots folder
    assert scans.screenshot_file("s1", "gowitness/screenshots/login.jpeg") is not None
    for scan, rel in [("s1", "output.json"), ("s1", "output.json.bak"), ("s1", "gowitness/screenshots/../../output.json"),
                      ("..", "s1/gowitness/screenshots/login.jpeg"), ("s1", "gowitness/screenshots/missing.png"),
                      ("s1", "/etc/passwd"), ("", "x.jpeg")]:  # fmt: skip
        assert scans.screenshot_file(scan, rel) is None, (scan, rel)


def test_screenshot_list_across_scans_and_codes(tmp_env):
    url = ev("U:9", "URL", "http://acme.example/", parent="D:1", module="http", host="acme.example",
             tags=TAGS + ["status-301"])  # fmt: skip
    shot = ev("W:9", "WEBSCREENSHOT", data_json={"path": "gowitness/screenshots/a.jpeg", "url": "https://acme.example/",
              "status_code": 403, "title": "Forbidden", "requested_url": "http://acme.example/", "status_reason": "Forbidden",
              "redirect_chain": [{"url": "http://acme.example/", "code": 301}, {"url": "https://acme.example/", "code": 403}]},
              parent="U:9", module="gowitness")  # fmt: skip
    broken = ev("W:8", "WEBSCREENSHOT", data_json={"path": "gowitness/screenshots", "url": "https://b.acme.example/"},
                parent="U:9", module="gowitness")  # fmt: skip
    write_scan(tmp_env, "base", BASE_EVENTS)
    d = write_scan(tmp_env, "base-enrich-1", [url, shot, broken])
    (d / "enrich.json").write_text(json.dumps({"parent": "base"}))
    (d / "gowitness" / "screenshots").mkdir(parents=True)
    (d / "gowitness" / "screenshots" / "a.jpeg").write_bytes(b"\xff\xd8\xff")
    every = scans.list_screenshots()
    # the folder-only path of a failed shot is not listed
    assert len(every["shots"]) == 1
    s = every["shots"][0]
    assert (s["scan"], s["root"], s["page"], s["url"], s["status_code"]) == (
        "base-enrich-1", "base", "http://acme.example/", "https://acme.example/", 403)
    assert s["code_from"] == "browser"
    # the redirect chain, the requested URL and the reason travel through to the Screenshots tab
    assert s["requested_url"] == "http://acme.example/" and s["status_reason"] == "Forbidden"
    assert [h["url"] for h in s["redirect_chain"]] == ["http://acme.example/", "https://acme.example/"]
    assert every["scans"] == [{"name": "base-enrich-1", "root": "base", "count": 1}]
    # asked for the original scan: its enrichments' screenshots come with it
    assert len(scans.list_screenshots("base")["shots"]) == 1
    found = {(f["type"], f["data"]): f for f in scans.aggregate_scan(d / "output.json")}
    assert found[("WEBSCREENSHOT", "https://acme.example/")]["http_status"] == [403]
    assert found[("URL", "http://acme.example/")]["screenshots"][0]["status_code"] == 403


def test_old_screenshot_takes_the_code_of_its_url(tmp_env):
    url = ev("U:9", "URL", "http://acme.example/", parent="D:1", module="http", host="acme.example",
             tags=TAGS + ["status-301"])  # fmt: skip
    shot = ev("W:9", "WEBSCREENSHOT", data_json={"path": "gowitness/screenshots/a.jpeg", "url": "https://acme.example/"},
              parent="U:9", module="gowitness")  # fmt: skip
    d = write_scan(tmp_env, "old", [url, shot])
    (d / "gowitness" / "screenshots").mkdir(parents=True)
    (d / "gowitness" / "screenshots" / "a.jpeg").write_bytes(b"\xff\xd8\xff")
    s = scans.list_screenshots()["shots"][0]
    assert (s["status_code"], s["code_from"]) == (301, "http")
