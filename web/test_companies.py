"""Tests for cron parsing, the company registry diff, Telegram alert rules and the scheduler:
`bbot/.venv/bin/pytest web/test_companies.py -q`."""

from datetime import datetime

import pytest

import companies
import cronexpr
import notify
import scans
import store


@pytest.fixture(autouse=True)
def tmp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DB_PATH", tmp_path / "tokosint.db")
    store.init()


def finding(data, type_="DNS_NAME", status="valid", tags=()):
    return {
        "type": type_,
        "data": data,
        "status": status,
        "sources": ["crt"],
        "tags": list(tags),
        "details": {},
    }


# ---------- cron ----------


def test_cron_steps_and_lists():
    assert cronexpr.next_run("*/15 * * * *", datetime(2026, 1, 1, 10, 7)) == datetime(
        2026, 1, 1, 10, 15
    )
    assert cronexpr.next_run("0 9,18 * * *", datetime(2026, 1, 1, 9, 0)) == datetime(
        2026, 1, 1, 18, 0
    )
    assert cronexpr.next_run("@daily", datetime(2026, 1, 1, 10, 0)) == datetime(
        2026, 1, 2, 0, 0
    )


def test_cron_weekdays_and_names():
    # 2026-01-03 is a Saturday -> next weekday 09:00 is Monday 2026-01-05
    assert cronexpr.next_run(
        "0 9 * * mon-fri", datetime(2026, 1, 3, 12, 0)
    ) == datetime(2026, 1, 5, 9, 0)
    assert cronexpr.next_run("0 0 * * 7", datetime(2026, 1, 3, 12, 0)) == datetime(
        2026, 1, 4, 0, 0
    )  # 7 = Sunday
    assert cronexpr.next_run("30 6 1 jan *", datetime(2026, 3, 1)) == datetime(
        2027, 1, 1, 6, 30
    )


def test_cron_leap_day_and_dom_dow_or():
    assert cronexpr.next_run("0 0 29 2 *", datetime(2026, 3, 1)) == datetime(
        2028, 2, 29, 0, 0
    )
    # classic cron: day 13 OR Friday; 2026-02-06 is a Friday, before the 13th
    assert cronexpr.next_run("0 0 13 * fri", datetime(2026, 2, 1)) == datetime(
        2026, 2, 6, 0, 0
    )


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "* * * *",
        "61 * * * *",
        "* 24 * * *",
        "*/0 * * * *",
        "5-1 * * * *",
        "x * * * *",
    ],
)
def test_cron_invalid(bad):
    with pytest.raises(cronexpr.CronError):
        cronexpr.validate(bad)


# ---------- registry diff ----------


def test_baseline_then_new_and_idempotent():
    co = store.save_company({"name": "Acme", "targets": []})
    store.link_scan("s1", co["id"], started_at=1000)
    r1 = store.ingest(
        "s1",
        [finding("a.acme.example"), finding("old.acme.example", status="historical")],
        1000,
    )
    assert r1["baseline"] and [f["data"] for f in r1["new"]] == ["a.acme.example"]

    store.link_scan("s2", co["id"], started_at=2000)
    r2 = store.ingest(
        "s2",
        [
            finding("a.acme.example"),
            finding("b.acme.example"),
            finding("mx.provider.example", tags=["third-party"]),
        ],
        2000,
    )
    assert not r2["baseline"]
    assert {f["data"] for f in r2["new"]} == {"b.acme.example", "mx.provider.example"}
    assert store.ingest("s2", [finding("c.acme.example")], 2000)[
        "skipped"
    ]  # same scan twice: no-op

    tl = store.timeline(co["id"])
    kinds = {(e["data"], e["kind"]) for e in tl["events"]}
    assert ("a.acme.example", "baseline") in kinds and (
        "b.acme.example",
        "new",
    ) in kinds
    assert (
        "old.acme.example",
        "baseline",
    ) not in kinds  # historical findings are not in the timeline
    assert [e for e in tl["events"] if e["data"] == "mx.provider.example"][0][
        "third_party"
    ] is True
    assert tl["new_by_type"] == {"DNS_NAME": 2}

    store.reset_registry(co["id"])
    assert store.timeline(co["id"])["events"] == []
    assert store.ingest("s1", [finding("a.acme.example")], 1000)["baseline"]


def test_company_validation_and_delete():
    store.save_company({"name": "Acme"})
    with pytest.raises(store.StoreError):
        store.save_company({"name": "Acme"})
    with pytest.raises(store.StoreError):
        store.save_company({"name": ""})
    co = store.save_company(
        {"name": "Beta", "targets": ["beta.example"]}, parse_targets=scans.parse_targets
    )
    assert co["targets"] == ["beta.example"]
    store.delete_company(co["id"])
    assert [c["name"] for c in store.list_companies()] == ["Acme"]


# ---------- alerts ----------


def test_alert_rules(monkeypatch):
    sent = []
    monkeypatch.setattr(
        notify,
        "send",
        lambda text, chat_id=None: sent.append((text, chat_id)) or (True, "ok"),
    )
    company = {
        "name": "Acme <Co>",
        "alerts_enabled": 1,
        "alert_types": ["OPEN_TCP_PORT"],
        "telegram_chat_id": "",
    }
    new = [
        finding("b.acme.example"),
        finding("b.acme.example:8443", type_="OPEN_TCP_PORT"),
    ]

    assert (
        notify.alert_new_findings(company, "s", {"baseline": True, "new": new})
        == "baseline: no alert"
    )
    assert (
        notify.alert_new_findings(company, "s", {"baseline": False, "new": new[:1]})
        == "nothing new to alert"
    )
    assert sent == []
    assert (
        notify.alert_new_findings(company, "s", {"baseline": False, "new": new})
        == "alert sent (1)"
    )
    text = sent[0][0]
    assert (
        "OPEN_TCP_PORT: 1" in text
        and "b.acme.example:8443" in text
        and "Acme &lt;Co&gt;" in text
    )
    assert "b.acme.example</" not in text.replace(
        "8443", ""
    )  # the DNS_NAME is filtered out by alert_types
    company["alerts_enabled"] = 0
    assert (
        notify.alert_new_findings(company, "s", {"baseline": False, "new": new})
        == "alerts disabled for the company"
    )


def test_settings_token_never_returned():
    notify.save_settings({"token": "123456:ABCDEFGHIJKLMNOP", "chat_id": "-100123"})
    view = notify.settings_view()
    assert (
        view["token_set"]
        and view["token_masked"].endswith("MNOP")
        and "123456" not in str(view)
    )
    with pytest.raises(store.StoreError):
        notify.save_settings({"token": "not a token"})


# ---------- scheduler ----------


def test_scheduler_runs_due_and_waits_for_busy_slot(monkeypatch):
    co = store.save_company(
        {"name": "Acme", "targets": ["acme.example"]}, parse_targets=scans.parse_targets
    )
    sched = store.save_schedule(
        {"company_id": co["id"], "cron": "0 3 * * *"}, next_run=0
    )  # missed run
    started = []
    monkeypatch.setattr(
        companies,
        "start_company_scan",
        lambda cid, mods, known, schedule_id=None: (
            started.append(cid) or {"name": "acme_1"}
        ),
    )

    monkeypatch.setattr(scans, "has_capacity", lambda: False)
    companies.tick(lambda: set())
    s = store.list_schedules()[0]
    assert (
        started == [] and s["pending"] == 1 and s["next_run"] > 0
    )  # waits for a free slot

    monkeypatch.setattr(scans, "has_capacity", lambda: True)
    companies.tick(lambda: set())
    s = store.list_schedules()[0]
    assert started == [co["id"]] and s["pending"] == 0 and s["last_scan"] == "acme_1"

    companies.tick(lambda: set())
    assert started == [co["id"]]  # next run is in the future
    assert s["id"] == sched["id"]
