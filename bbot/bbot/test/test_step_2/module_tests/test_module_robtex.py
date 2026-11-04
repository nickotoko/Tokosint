import json
import time

from .base import ModuleTestBase


now = int(time.time())
old = now - 400 * 86400


def ndjson(*records):
    return "\n".join(json.dumps(r) for r in records)


class TestRobtex(ModuleTestBase):
    targets = ["blacklanternsecurity.com", "1.2.3.4", "5.6.7.8"]
    config_overrides = {
        # фильтр shared hosting самого модуля; имена вне скоупа validity скрывает (D-021), здесь это не проверяется
        "modules": {
            "robtex": {"requests_per_minute": 6000, "max_reverse_names": 2},
            "validity": {"relation_check": False},
        },
        "scope": {"report_distance": 2},
    }

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                "ns1.blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                "brand.blacklanternsecurity.com": {"A": ["1.2.3.4"]},
            }
        )
        module_test.blasthttp_mock.add_response(
            url="https://freeapi.robtex.com/pdns/forward/blacklanternsecurity.com",
            match_headers={"User-Agent": "bbot"},
            text=ndjson(
                {
                    "rrname": "blacklanternsecurity.com",
                    "rrdata": "9.9.9.9",
                    "rrtype": "A",
                    "time_first": old,
                    "time_last": old,
                },
                {
                    "rrname": "blacklanternsecurity.com",
                    "rrdata": "ns1.blacklanternsecurity.com",
                    "rrtype": "NS",
                    "time_first": old,
                    "time_last": now,
                },
                {
                    "rrname": "blacklanternsecurity.com",
                    "rrdata": "v=spf1 -all",
                    "rrtype": "TXT",
                    "time_first": old,
                    "time_last": now,
                },
            ),
        )
        module_test.blasthttp_mock.add_response(
            url="https://freeapi.robtex.com/pdns/reverse/1.2.3.4",
            text=ndjson(
                {
                    "rrname": "brand.blacklanternsecurity.com",
                    "rrdata": "1.2.3.4",
                    "rrtype": "A",
                    "time_first": old,
                    "time_last": now,
                }
            ),
        )
        # an IP in the target's own network may have many names (other brands of the organisation)
        module_test.blasthttp_mock.add_response(
            url="https://freeapi.robtex.com/pdns/reverse/9.9.9.9",
            text=ndjson(
                *[
                    {
                        "rrname": f"brand{i}.blacklanternsecurity-group.com",
                        "rrdata": "9.9.9.9",
                        "rrtype": "A",
                        "time_first": now,
                        "time_last": now,
                    }
                    for i in range(5)
                ]
            ),
        )
        module_test.blasthttp_mock.add_response(
            url="https://freeapi.robtex.com/ipquery/9.9.9.9",
            text=json.dumps(
                {"status": "ok", "as": 64500, "asname": "BLS-AS", "routedesc": '"BLACKLANTERNSECURITY" LLC'}
            ),
        )
        module_test.blasthttp_mock.add_response(
            url="https://freeapi.robtex.com/ipquery/5.6.7.8",
            text=json.dumps({"status": "ok", "as": 64501, "asname": "HOSTER-AS", "routedesc": "Some Hosting Ltd"}),
        )
        # an IP with many names is shared hosting: its reverse results must not be used
        module_test.blasthttp_mock.add_response(
            url="https://freeapi.robtex.com/pdns/reverse/5.6.7.8",
            text=ndjson(
                *[
                    {
                        "rrname": f"site{i}.example.org",
                        "rrdata": "5.6.7.8",
                        "rrtype": "A",
                        "time_first": now,
                        "time_last": now,
                    }
                    for i in range(5)
                ]
            ),
        )

    def check(self, module_test, events):
        mine = {e.data: e for e in events if str(e.module) == "robtex"}
        assert "9.9.9.9" in mine and mine["9.9.9.9"].type == "IP_ADDRESS", "Failed to emit historical IP"
        assert "pdns-historical" in mine["9.9.9.9"].tags
        assert (
            "ns1.blacklanternsecurity.com" in mine
            and "pdns-historical" not in mine["ns1.blacklanternsecurity.com"].tags
        )
        assert "brand.blacklanternsecurity.com" in mine, "Failed to use reverse pDNS"
        assert not any(d.endswith("example.org") for d in mine), "shared-hosting IP must be skipped"
        assert "seen " in mine["brand.blacklanternsecurity.com"].discovery_context
        assert "brand1.blacklanternsecurity-group.com" in mine, "own-network IP should allow more reverse names"
