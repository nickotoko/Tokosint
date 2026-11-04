from .base import ModuleTestBase
from bbot.test.mock_blasthttp import MockResponse


dns = {
    "blacklanternsecurity.com": {"A": ["127.0.0.1"]},
    "asdf.blacklanternsecurity.com": {"A": ["127.0.0.1"]},
    "zzzz.blacklanternsecurity.com": {"A": ["127.0.0.1"]},
}


def row(domain, timestamp="2026-10-20T11:31:33.072Z"):
    return {"data": {"@timestamp": timestamp, "zone": "com", "domain": domain}, "scan_label": "2026-10-01"}


class TestNetlas(ModuleTestBase):
    """Without a key, only the first search page is used."""

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(dns)
        module_test.blasthttp_mock.add_response(
            url="https://app.netlas.io/api/domains/?q=domain%3A%2A.blacklanternsecurity.com&start=0",
            json={"items": [row("asdf.blacklanternsecurity.com")]},
        )

    def check(self, module_test, events):
        names = {e.data: e for e in events if e.type == "DNS_NAME" and str(e.module) == "netlas"}
        assert "asdf.blacklanternsecurity.com" in names, "Failed to detect subdomain"
        assert "seen 2026-10-20" in names["asdf.blacklanternsecurity.com"].discovery_context


class TestNetlas_ApiKey(ModuleTestBase):
    """With a key, the full list is downloaded (capped by max_results)."""

    module_name = "netlas"
    config_overrides = {"modules": {"netlas": {"api_key": "asdf", "max_results": 2}}}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(dns)
        auth = {"Authorization": "Bearer asdf"}
        module_test.blasthttp_mock.add_response(
            url="https://app.netlas.io/api/domains_count/?q=domain%3A%2A.blacklanternsecurity.com",
            match_headers=auth,
            json={"count": 43},
        )
        module_test.blasthttp_mock.add_response(
            url="https://app.netlas.io/api/domains/download/",
            method="POST",
            match_headers=auth,
            json=[row("asdf.blacklanternsecurity.com"), row("zzzz.blacklanternsecurity.com")],
        )

    def check(self, module_test, events):
        names = {e.data for e in events if e.type == "DNS_NAME" and str(e.module) == "netlas"}
        assert names == {"asdf.blacklanternsecurity.com", "zzzz.blacklanternsecurity.com"}, names


class TestNetlas_DailyLimit(ModuleTestBase):
    """The daily quota error is final: no retries, no sleeping, no results."""

    module_name = "netlas"

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(dns)
        module_test.requests = 0

        def daily_limit(request):
            module_test.requests += 1
            return MockResponse(
                status_code=429,
                json={"type": "daily_request_limit_exceeded", "detail": "Daily request limit exceeded"},
            )

        module_test.blasthttp_mock.add_callback(
            daily_limit, url="https://app.netlas.io/api/domains/?q=domain%3A%2A.blacklanternsecurity.com&start=0"
        )

    def check(self, module_test, events):
        assert module_test.requests == 1, "daily limit must not be retried"
        assert not any(str(e.module) == "netlas" for e in events)
