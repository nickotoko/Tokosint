import base64
import datetime
import re
from urllib.parse import parse_qs, urlparse

from .base import ModuleTestBase
from bbot.test.mock_blasthttp import MockResponse

CST = datetime.timezone(datetime.timedelta(hours=8))


def fofa_date(days_ago):
    """A FOFA-style date (China time) `days_ago` days before now."""
    return (datetime.datetime.now(CST) - datetime.timedelta(days=days_ago)).strftime("%Y-%m-%d %H:%M:%S")


class TestFofa(ModuleTestBase):
    targets = ["blacklanternsecurity.com", "1.2.3.4"]
    # distance-1 findings (ports on addresses) are reported, as in the project config
    config_overrides = {"scope": {"report_distance": 1}, "modules": {"fofa": {"api_key": "asdf"}}}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                "asdf.blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                "fresh.blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                "stale.blacklanternsecurity.com": {"A": ["1.2.3.4"]},
            }
        )
        # IPs of someone else's infrastructure get no host details
        module = module_test.scan.modules["fofa"]
        self.filtered = {}
        for tag in ("ip-proxy", "cdn-cloudflare", "third-party", None):
            ip = module.make_event(
                "5.6.7.8", "IP_ADDRESS", parent=module_test.scan.root_event, tags=[tag] if tag else []
            )
            self.filtered[tag] = await module.filter_event(ip)
        name = module.make_event("other.example", "DNS_NAME", parent=module_test.scan.root_event)
        name.scope_distance = 1
        self.filtered["out-of-scope name"] = await module.filter_event(name)

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="https://fofa.info/api/v1/info/my?key=asdf",
            json={"error": False, "email": "test@example.com"},
        )
        module_test.blasthttp_mock.add_response(
            url=re.compile(r"https://fofa\.info/api/v1/search/all\?qbase64=.+&key=asdf"),
            json={
                "error": False,
                "results": [
                    [
                        "https://asdf.blacklanternsecurity.com:8443",
                        "1.2.3.4",
                        "8443",
                        "*.blacklanternsecurity.com",
                        "2024-05-01 10:00:00",
                    ],
                    ["1.2.3.4:22", "1.2.3.4", "22", ""],
                    # seen by FOFA two days ago: current; a year ago: historical
                    ["https://fresh.blacklanternsecurity.com", "1.2.3.4", "443", "", fofa_date(2)],
                    ["https://stale.blacklanternsecurity.com", "1.2.3.4", "443", "", fofa_date(365)],
                    # a name that only ends with the same letters (FOFA's *= is a substring match)
                    ["https://evilblacklanternsecurity.com", "6.6.6.6", "443", "evilblacklanternsecurity.com"],
                    ["https://www.notblacklanternsecurity.com", "6.6.6.7", "443", "*.notblacklanternsecurity.com"],
                    # a foreign name presenting the target's certificate: the address is kept, the name is not
                    ["https://cdn-front.example", "7.7.7.7", "443", "*.blacklanternsecurity.com"],
                    # an IP with an unrelated certificate
                    ["https://8.8.8.1", "8.8.8.1", "443", "other.example"],
                ],
            },
        )
        module_test.blasthttp_mock.add_response(
            url="https://fofa.info/api/v1/host/1.2.3.4?detail=true&key=asdf",
            json={
                "error": False,
                "ports": [
                    {"port": 8080, "update_time": fofa_date(1), "products": [{"product": "nginx"}]},
                    {"port": 2222, "update_time": fofa_date(30)},
                ],
            },
        )

    def check(self, module_test, events):
        assert any(e.type == "DNS_NAME" and e.data == "asdf.blacklanternsecurity.com" for e in events), (
            "Failed to detect subdomain"
        )
        hostport = next(
            e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "asdf.blacklanternsecurity.com:8443"
        )
        # the date FOFA last saw the service (China time, UTC+8), not the scan time
        assert hostport.last_seen == 1714528800.0
        assert hostport.json()["last_seen"] == 1714528800.0
        assert "validity-historical" in hostport.tags, "seen by FOFA in 2024"
        fresh = next(e for e in events if e.data == "fresh.blacklanternsecurity.com:443")
        assert {"validity-valid", "freshness-current", "seen-recently"} <= fresh.tags, fresh.tags
        stale = next(e for e in events if e.data == "stale.blacklanternsecurity.com:443")
        assert "validity-historical" in stale.tags and "seen-recently" not in stale.tags, stale.tags
        # no date from the source - no last_seen
        assert next(e for e in events if e.data == "1.2.3.4:22").last_seen is None
        port = next((e for e in events if e.type == "OPEN_TCP_PORT" and e.data == "1.2.3.4:8080"), None)
        assert port is not None, "Failed to detect open port from host details"
        assert port.parent.type == "IP_ADDRESS" and port.parent.data == "1.2.3.4", "host details hang off the IP"
        assert {"validity-valid", "seen-recently"} <= port.tags, "host details: port seen yesterday"
        old_port = next(e for e in events if e.data == "1.2.3.4:2222")
        assert "validity-historical" in old_port.tags, "host details: port seen a month ago"
        assert any(e.type == "TECHNOLOGY" and e.data["technology"] == "nginx" and e.port == 8080 for e in events), (
            "Failed to detect technology"
        )
        # ports must be attached to the host they were observed on, not to the queried domain
        assert not any(e.type == "OPEN_TCP_PORT" and e.data == "blacklanternsecurity.com:8080" for e in events)
        # substring matches are dropped
        for junk in ("evilblacklanternsecurity.com", "www.notblacklanternsecurity.com", "6.6.6.6", "6.6.6.7"):
            assert not any(junk in str(e.data) for e in events), f"{junk} is not related to the target"
        assert any(e.type == "OPEN_TCP_PORT" and e.data == "7.7.7.7:443" for e in events), "cert-matched address"
        assert not any("cdn-front.example" in str(e.data) for e in events), "foreign name of a cert match"
        assert not any("8.8.8.1" in str(e.data) for e in events), "unrelated certificate"
        assert self.filtered[None] is True
        for tag in ("ip-proxy", "cdn-cloudflare", "third-party", "out-of-scope name"):
            assert self.filtered[tag] is not True and self.filtered[tag][0] is False, tag


class TestFofaNoHostDetails(TestFofa):
    module_name = "fofa"
    config_overrides = {"modules": {"fofa": {"api_key": "asdf", "host_details": False}}}

    def check(self, module_test, events):
        assert any(e.type == "OPEN_TCP_PORT" and e.data == "asdf.blacklanternsecurity.com:8443" for e in events)
        assert not any(e.type == "OPEN_TCP_PORT" and e.data == "1.2.3.4:8080" for e in events)
        assert not any(e.type == "TECHNOLOGY" for e in events)


class TestFofaNoFieldPermissionPaging(ModuleTestBase):
    """A key without permission for lastupdatetime (FOFA error 820001, HTTP 200): the search is repeated without
    the field instead of silently returning nothing; results past the first page are fetched too."""

    module_name = "fofa"
    targets = ["blacklanternsecurity.com"]
    config_overrides = {"modules": {"fofa": {"api_key": "asdf", "size": 2, "host_details": False}}}
    search = r"https://fofa\.info/api/v1/search/all\?qbase64=[^&]+&fields="

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                "a.blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                "b.blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                "paged.blacklanternsecurity.com": {"A": ["1.2.3.4"]},
            }
        )

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="https://fofa.info/api/v1/info/my?key=asdf", json={"error": False, "email": "test@example.com"}
        )
        module_test.blasthttp_mock.add_response(
            url=re.compile(self.search + r"[^&]*lastupdatetime[^&]*&.*key=asdf"),
            json={"error": True, "errmsg": "[820001] 没有权限搜索lastupdatetime字段"},
        )
        module_test.blasthttp_mock.add_response(
            url=re.compile(self.search + r"(?![^&]*lastupdatetime)[^&]*&size=2&page=1&key=asdf"),
            json={
                "error": False,
                "size": 3,
                "results": [
                    ["https://a.blacklanternsecurity.com", "1.2.3.4", "443", ""],
                    ["b.blacklanternsecurity.com:80", "1.2.3.4", "80", ""],
                ],
            },
        )
        module_test.blasthttp_mock.add_response(
            url=re.compile(self.search + r"(?![^&]*lastupdatetime)[^&]*&size=2&page=2&key=asdf"),
            json={"error": False, "size": 3, "results": [["paged.blacklanternsecurity.com", "1.2.3.4", "80", ""]]},
        )

    def check(self, module_test, events):
        names = {e.data for e in events if e.type == "DNS_NAME"}
        for name in ("a.blacklanternsecurity.com", "b.blacklanternsecurity.com", "paged.blacklanternsecurity.com"):
            assert name in names, f"{name} missing: {names}"
        assert any(e.type == "OPEN_TCP_PORT" and e.data == "paged.blacklanternsecurity.com:80" for e in events)
        module = module_test.scan.modules["fofa"]
        assert module._search_fields == module.base_search_fields


class TestFofaRecentQuery(ModuleTestBase):
    """A key without lastupdatetime: the domain search is repeated with after=<scan date - recent_days>; results in
    both answers are current (valid), the rest historical. With recent_query off - no second query."""

    module_name = "fofa"
    targets = ["blacklanternsecurity.com"]
    config_overrides = {"modules": {"fofa": {"api_key": "asdf", "host_details": False}}}
    recent_query = True

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                "live.blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                "old.blacklanternsecurity.com": {"A": ["1.2.3.4"]},
            }
        )

    async def setup_before_prep(self, module_test):
        self.queries = []
        module_test.blasthttp_mock.add_response(
            url="https://fofa.info/api/v1/info/my?key=asdf", json={"error": False, "email": "test@example.com"}
        )
        everything = [
            ["https://live.blacklanternsecurity.com", "1.2.3.4", "443", ""],
            ["old.blacklanternsecurity.com:8080", "1.2.3.4", "8080", ""],
        ]

        async def search(request):
            params = parse_qs(urlparse(str(request.url)).query)
            if "lastupdatetime" in params["fields"][0]:
                return MockResponse(status_code=200, json={"error": True, "errmsg": "[820001] no permission"})
            query = base64.b64decode(params["qbase64"][0]).decode()
            self.queries.append(query)
            results = everything[:1] if "after=" in query else everything
            return MockResponse(status_code=200, json={"error": False, "size": len(results), "results": results})

        module_test.blasthttp_mock.add_callback(search, url=re.compile(r"https://fofa\.info/api/v1/search/all\?"))

    def check(self, module_test, events):
        cutoff = (datetime.datetime.now(CST) - datetime.timedelta(days=7)).strftime("%Y-%m-%d")
        recent = [q for q in self.queries if "after=" in q]
        live = next(e for e in events if e.data == "live.blacklanternsecurity.com:443")
        old = next(e for e in events if e.data == "old.blacklanternsecurity.com:8080")
        assert "validity-historical" in old.tags, old.tags
        if not self.recent_query:
            assert not recent, self.queries
            assert "validity-historical" in live.tags, live.tags
            return
        # every searched domain (the target and the subdomains found) is asked once more, limited to recent results
        assert (
            f'(domain="blacklanternsecurity.com" || cert.subject.cn="blacklanternsecurity.com" || '
            f'cert.subject.cn*="*.blacklanternsecurity.com") && after="{cutoff}"'
        ) in recent, self.queries
        assert len(recent) == len(self.queries) - len(recent), self.queries
        assert {"validity-valid", "freshness-current", "seen-recently"} <= live.tags, live.tags
        assert f"seen by FOFA since {cutoff}" in live.discovery_context
        name = next(e for e in events if e.type == "DNS_NAME" and e.data == "live.blacklanternsecurity.com")
        assert "seen-recently" in name.tags


class TestFofaRecentQueryOff(TestFofaRecentQuery):
    config_overrides = {"modules": {"fofa": {"api_key": "asdf", "host_details": False, "recent_query": False}}}
    recent_query = False
