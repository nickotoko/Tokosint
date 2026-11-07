import json
import time

from .base import ModuleTestBase

BLS = "blacklanternsecurity.com"
URL = "https://www.circl.lu/pdns/query"
AUTH = "Basic dXNlcjpwYXNz"  # user:pass
now = int(time.time())
old = now - 400 * 86400


def ndjson(*records):
    return "\n".join(json.dumps(r) for r in records)


def rec(rrname, rrtype, rdata, last=now):
    return {"rrname": rrname, "rrtype": rrtype, "rdata": rdata, "time_first": old, "time_last": last, "count": 3}


class TestCirclPdns(ModuleTestBase):
    module_name = "circl_pdns"
    targets = [BLS, "1.2.3.4"]
    config_overrides = {
        "modules": {
            "circl_pdns": {"username": "user", "password": "pass", "max_reverse_names": 2},
            "validity": {"relation_check": False},
        },
        # tests the module's own parsing and shared-hosting filter; validity hides unproven out-of-scope names
        "scope": {"report_distance": 2},
    }

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {BLS: {"A": ["1.2.3.4"]}, f"ns1.{BLS}": {"A": ["1.2.3.5"]}, "mx.mailhost.io": {"A": ["5.5.5.5"]}}
        )
        # page 2 of the forward query (the cursor from page 1)
        module_test.blasthttp_mock.add_response(
            url=f"{URL}/{BLS}",
            match_headers={"Authorization": AUTH, "dribble-paginate-cursor": "50"},
            text=ndjson(rec(BLS, "MX", "10 mx.mailhost.io")),
        )
        module_test.blasthttp_mock.add_response(
            url=f"{URL}/{BLS}",
            match_headers={"Authorization": AUTH, "dribble-disable-active-query": "1"},
            headers={"x-dribble-cursor": "50"},
            text=ndjson(
                rec(BLS, "A", "9.9.9.9", last=old),
                rec(BLS, "NS", ["ns1.blacklanternsecurity.com."]),
                rec(BLS, "TXT", "v=spf1 -all"),
                # another name's record in the answer: not a record of the queried name
                rec(f"other.{BLS}", "A", "8.8.4.4"),
            ),
        )
        module_test.blasthttp_mock.add_response(
            url=f"{URL}/1.2.3.4",
            match_headers={"Authorization": AUTH},
            text=ndjson(rec(f"brand.{BLS}", "A", "1.2.3.4")),
        )
        # shared hosting: more names than max_reverse_names -> ignored
        module_test.blasthttp_mock.add_response(
            url=f"{URL}/9.9.9.9",
            match_headers={"Authorization": AUTH},
            text=ndjson(*[rec(f"site{i}.unrelated.example.org", "A", "9.9.9.9") for i in range(5)]),
        )

    def check(self, module_test, events):
        found = {(e.type, e.data): e for e in events if str(e.module) == "circl_pdns"}
        ip = found[("IP_ADDRESS", "9.9.9.9")]
        assert "pdns-historical" in ip.tags
        assert "CIRCL passive DNS (A record of blacklanternsecurity.com" in ip.discovery_context
        assert ("DNS_NAME", f"ns1.{BLS}") in found
        assert "pdns-historical" not in found[("DNS_NAME", f"ns1.{BLS}")].tags
        # MX from the second page, priority stripped
        assert ("DNS_NAME", "mx.mailhost.io") in found
        # reverse lookup of the target IP
        assert f"brand.{BLS}" in {d for _, d in found}
        assert not any(d == "8.8.4.4" for _, d in found), "records of other names must not be emitted"
        assert not any("unrelated.example.org" in str(d) for _, d in found), "shared hosting must be skipped"
        # every API request is counted for the scan report (module_stats.json)
        stat = module_test.scan.stats.module_stats["circl_pdns"]
        # 4 mocked answers (2 pages + 2 reverse lookups); unmocked lookups get no answer -> unavailable
        assert stat.requests.get("ok") == 4
        assert stat.requests_total == 4 + stat.requests.get("unavailable", 0)


class TestCirclPdns_NoCredentials(ModuleTestBase):
    module_name = "circl_pdns"
    targets = [BLS]

    def check(self, module_test, events):
        assert "circl_pdns" not in module_test.scan.modules


class TestCirclPdns_SwappedCredentials(ModuleTestBase):
    """The e-mail typed into the token field and the token into the e-mail field still authenticates as e-mail:token."""

    module_name = "circl_pdns"
    targets = [BLS]
    config_overrides = {"modules": {"circl_pdns": {"username": "TOKEN123", "password": "me@example.org"}}}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns({BLS: {"A": ["1.2.3.4"]}})
        module_test.blasthttp_mock.add_response(
            url=f"{URL}/{BLS}",
            match_headers={"Authorization": "Basic bWVAZXhhbXBsZS5vcmc6VE9LRU4xMjM="},  # me@example.org:TOKEN123
            text=ndjson(rec(BLS, "NS", "ns1.blacklanternsecurity.com")),
        )

    def check(self, module_test, events):
        assert any(e.data == f"ns1.{BLS}" and str(e.module) == "circl_pdns" for e in events)
