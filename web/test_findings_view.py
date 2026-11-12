"""The cross-company Findings view: union across a company's scans, dedup, status overrides and filters."""

import eventdb
import findings
import pytest
import store

import scans


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DB_PATH", tmp_path / "tokosint.db")
    monkeypatch.setattr(eventdb, "SCANS_DIR", tmp_path / "scans")
    store.init()
    eventdb.init()
    return tmp_path


def _finding(type_, data, risk, status="valid", category="exposure", **extra):
    f = {"type": type_, "data": data, "risk": risk, "risk_reasons": [f"{risk} reason"], "risk_category": category,
         "status": status, "sources": extra.get("sources", []), "hosts": extra.get("hosts", []),
         "ports": extra.get("ports", []), "http_status": extra.get("http_status", []), "tags": extra.get("tags", []),
         "details": {}, "screenshots": extra.get("screenshots", []), "last_seen": extra.get("last_seen")}  # fmt: skip
    return f


def _company_with_scans(name, scan_findings):
    co = store.save_company(
        {"name": name, "targets": ["acme.example"]}, parse_targets=scans.parse_targets
    )
    for scan, flist in scan_findings.items():
        store.link_scan(scan, co["id"])
        eventdb.store_findings(scan, flist)
    return co


def test_union_dedup_worst_risk_and_best_status(db):
    co = _company_with_scans("Acme", {
        "s1": [_finding("URL", "https://a/login", "high", "historical", sources=["gowitness"]),
               _finding("OPEN_TCP_PORT", "a:3389", "high", "valid")],
        "s2": [_finding("URL", "https://a/login", "medium", "valid", sources=["httpx"], ports=[443])],
    })  # fmt: skip
    res = findings.company_findings([co["id"]])
    by = {(f["type"], f["data"]): f for f in res["findings"]}
    login = by[("URL", "https://a/login")]
    assert login["risk"] == "high"  # worst risk across scans
    assert login["status"] == "valid"  # most-current status wins
    assert set(login["sources"]) == {"gowitness", "httpx"} and login["ports"] == [443]
    assert set(login["scans"]) == {"s1", "s2"}
    assert res["total"] == 2  # login (deduped) + rdp port


def test_filters(db):
    co = _company_with_scans(
        "Acme",
        {
            "s1": [
                _finding("URL", "https://a/login", "high", category="login"),
                _finding("OPEN_TCP_PORT", "a:9200", "medium", category="port"),
                _finding("FINDING", "exposed .git", "critical", category="exposure"),
            ]
        },
    )
    assert findings.company_findings([co["id"]], risk_level="critical")["total"] == 1
    assert findings.company_findings([co["id"]], category="login")["total"] == 1
    assert findings.company_findings([co["id"]], q="9200")["total"] == 1
    cats = {
        c["value"]: c["count"]
        for c in findings.company_findings([co["id"]])["facets"]["categories"]
    }
    assert cats == {"login": 1, "port": 1, "exposure": 1}
    facets = findings.company_findings([co["id"]])["facets"]
    assert [x["value"] for x in facets["risk"]] == [
        "critical",
        "high",
        "medium",
    ]  # ordered by severity


def test_all_companies_when_no_ids(db):
    _company_with_scans("A", {"sa": [_finding("URL", "https://a/login", "high")]})
    _company_with_scans("B", {"sb": [_finding("URL", "https://b/login", "low")]})
    res = findings.company_findings()  # no ids -> all companies
    names = {(f["company"], f["data"]) for f in res["findings"]}
    assert ("A", "https://a/login") in names and ("B", "https://b/login") in names


def test_override_false_hides_and_historical_downgrades(db):
    co = _company_with_scans(
        "Acme",
        {
            "s1": [
                _finding("OPEN_TCP_PORT", "a:3389", "high"),
                _finding("URL", "https://a/login", "high"),
            ]
        },
    )
    # mark the RDP port false -> gone from the view
    store.add_override("s1", "OPEN_TCP_PORT", "a:3389", "false")
    res = findings.company_findings([co["id"]])
    assert all(f["data"] != "a:3389" for f in res["findings"])
    assert res["total"] == 1


def test_company_finding_full_card(db):
    # the drill-down merges the whole cached records of the finding over the company's scans
    login1 = dict(_finding("URL", "https://a/login", "high", "historical", sources=["gowitness"]),
                  contexts=[{"module": "gowitness", "context": "screenshot of https://a/login"}],
                  details={"title": "Sign in"}, on=[], via=[], false_reasons=[], scan_date=1700000000.0)
    login2 = dict(_finding("URL", "https://a/login", "medium", "valid", sources=["httpx"], ports=[443]),
                  contexts=[{"module": "httpx", "context": "httpx visited https://a/login"}],
                  details={}, on=[], via=[], false_reasons=[], scan_date=1710000000.0, last_seen=1709000000.0)
    other = _finding("OPEN_TCP_PORT", "a:3389", "high")
    co = _company_with_scans("Acme", {"s1": [login1, other], "s2": [login2]})
    card = findings.company_finding(co["id"], "URL", "https://a/login")
    assert card["status"] == "valid" and set(card["scans"]) == {"s1", "s2"}
    assert set(card["sources"]) == {"gowitness", "httpx"} and card["ports"] == [443]
    assert [c["module"] for c in card["contexts"]] == ["gowitness", "httpx"]
    assert card["details"]["title"] == "Sign in"
    assert card["last_seen"] == 1709000000.0 and card["scan_date"] == 1710000000.0
    assert card["risk"]  # risk recomputed on the merged record
    assert findings.company_finding(co["id"], "URL", "https://a/missing") is None
    # another company does not see it
    co2 = _company_with_scans("Other", {"s3": []})
    assert findings.company_finding(co2["id"], "URL", "https://a/login") is None
