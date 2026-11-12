"""Importing a scan's events into the database, reading them back and safely deleting the JSON files."""

import json

import eventdb
import pytest
import store


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DB_PATH", tmp_path / "tokosint.db")
    monkeypatch.setattr(eventdb, "SCANS_DIR", tmp_path / "scans")
    store.init()
    eventdb.init()
    return tmp_path


def _write_scan(root, name, events, false=()):
    d = root / "scans" / name
    d.mkdir(parents=True)
    with open(d / "output.json", "w") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in events)
    if false:
        with open(d / "validity_false.jsonl", "w") as fh:
            fh.writelines(json.dumps(e) + "\n" for e in false)
    return d


SCAN_EVENT = {
    "type": "SCAN",
    "data_json": {"started_at": 1700000000.0, "target": {"seeds": ["example.com"]}},
}
EVENTS = [
    SCAN_EVENT,
    {"type": "DNS_NAME", "data": "example.com", "id": "DNS_NAME:1", "module": "SEED"},
    {
        "type": "DNS_NAME",
        "data": "www.example.com",
        "id": "DNS_NAME:2",
        "module": "crt",
    },
]
FALSE = [
    {
        "type": "DNS_NAME",
        "data": "stale.example.com",
        "module": "crt",
        "reason": "no longer resolves",
    }
]


def test_import_reads_back_identically(tmp_db):
    _write_scan(tmp_db, "s1", EVENTS, FALSE)
    rec = eventdb.import_scan("s1")
    assert rec["event_count"] == 3 and rec["false_count"] == 1
    assert rec["started_at"] == 1700000000.0 and rec["targets"] == ["example.com"]
    assert eventdb.is_imported("s1")
    # same dicts, same order
    assert eventdb.events_of("s1") == EVENTS
    assert eventdb.false_of("s1") == FALSE


def test_import_is_idempotent(tmp_db):
    _write_scan(tmp_db, "s1", EVENTS)
    eventdb.import_scan("s1")
    first = eventdb.import_record("s1")["imported_at"]
    again = eventdb.import_scan("s1")  # no replace -> unchanged
    assert again["imported_at"] == first
    assert len(eventdb.events_of("s1")) == 3  # not duplicated


def test_reimport_replace(tmp_db):
    d = _write_scan(tmp_db, "s1", EVENTS)
    eventdb.import_scan("s1")
    # the scan grew; re-import must replace, not append
    with open(d / "output.json", "a") as fh:
        fh.write(
            json.dumps(
                {
                    "type": "URL",
                    "data": "http://example.com",
                    "id": "URL:1",
                    "module": "httpx",
                }
            )
            + "\n"
        )
    rec = eventdb.import_scan("s1", replace=True)
    assert rec["event_count"] == 4
    assert len(eventdb.events_of("s1")) == 4


def test_delete_files_requires_import(tmp_db):
    _write_scan(tmp_db, "s1", EVENTS)
    with pytest.raises(store.StoreError) as e:
        eventdb.delete_files("s1")
    assert e.value.code == 409


def test_delete_files_after_import(tmp_db):
    d = _write_scan(tmp_db, "s1", EVENTS, FALSE)
    eventdb.import_scan("s1")
    res = eventdb.delete_files("s1")
    assert (
        set(res["deleted"]) == {"output.json", "validity_false.jsonl"}
        and res["freed_bytes"] > 0
    )
    assert (
        not (d / "output.json").exists() and not (d / "validity_false.jsonl").exists()
    )
    assert eventdb.import_record("s1")["files_deleted"] is True
    # events still readable from the database after the files are gone
    assert eventdb.events_of("s1") == EVENTS


def test_delete_refuses_on_mismatch(tmp_db):
    d = _write_scan(tmp_db, "s1", EVENTS)
    eventdb.import_scan("s1")
    with open(d / "output.json", "a") as fh:  # file changed after import, counts differ
        fh.write(
            json.dumps(
                {
                    "type": "URL",
                    "data": "http://example.com",
                    "id": "URL:9",
                    "module": "httpx",
                }
            )
            + "\n"
        )
    with pytest.raises(store.StoreError) as e:
        eventdb.delete_files("s1")
    assert e.value.code == 409 and (d / "output.json").exists()
