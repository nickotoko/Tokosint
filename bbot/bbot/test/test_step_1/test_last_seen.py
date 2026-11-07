"""last_seen: the date the source last observed a finding (not the scan time)."""

import datetime

from bbot.core.event.base import event_from_json, make_event, parse_last_seen


def test_parse_last_seen():
    ts = 1714557600.0  # 2024-05-01 10:00:00 UTC
    assert parse_last_seen(ts) == ts
    assert parse_last_seen(int(ts * 1000)) == ts  # milliseconds
    assert parse_last_seen(str(int(ts))) == ts
    assert parse_last_seen("2024-05-01 10:00:00") == ts
    assert parse_last_seen("2024-05-01T10:00:00Z") == ts
    assert parse_last_seen("2024-05-01T10:00:00+00:00") == ts
    assert parse_last_seen("2024-05-01") == 1714521600.0
    assert parse_last_seen(datetime.datetime(2024, 5, 1, 10, tzinfo=datetime.timezone.utc)) == ts
    for empty in (None, "", "never", 0, True, "?"):
        assert parse_last_seen(empty) is None, empty


def test_last_seen_roundtrip():
    e = make_event("www.evilcorp.com", "DNS_NAME", dummy=True, last_seen="2024-05-01")
    assert e.last_seen == 1714521600.0
    j = e.json()
    assert j["last_seen"] == 1714521600.0
    assert event_from_json(dict(j, scope_distance=0)).last_seen == 1714521600.0
    # without a source date there is no field at all
    j = make_event("evilcorp.com", "DNS_NAME", dummy=True).json()
    assert "last_seen" not in j
