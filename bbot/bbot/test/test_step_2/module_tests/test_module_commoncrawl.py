import json

from .base import ModuleTestBase
from bbot.test.mock_blasthttp import MockResponse


index = "https://index.commoncrawl.org/CC-MAIN-2026-43-index?url=*.blacklanternsecurity.com&output=json&fl=url"


class TestCommonCrawl(ModuleTestBase):
    config_overrides = {"modules": {"commoncrawl": {"crawls": 1, "retries": 2}}}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["127.0.0.1"]},
                "asdf.blacklanternsecurity.com": {"A": ["127.0.0.1"]},
                "zzzz.blacklanternsecurity.com": {"A": ["127.0.0.1"]},
            }
        )
        # don't actually wait between retries
        module_test.module._retry_delays = (0,)
        module_test.blasthttp_mock.add_response(
            url="https://index.commoncrawl.org/collinfo.json",
            json=[{"id": "CC-MAIN-2026-43"}, {"id": "CC-MAIN-2026-33"}],
        )
        module_test.blasthttp_mock.add_response(url=f"{index}&showNumPages=true", json={"pages": 2})
        module_test.blasthttp_mock.add_response(
            url=f"{index}&page=0",
            text=json.dumps({"url": "https://asdf.blacklanternsecurity.com/index.html"}),
        )
        # the index is flaky: the second page fails once before succeeding
        module_test.page1_requests = 0

        def flaky_page(request):
            module_test.page1_requests += 1
            if module_test.page1_requests == 1:
                return MockResponse(status_code=504, text="504 Gateway Time-out")
            return MockResponse(text=json.dumps({"url": "http://zzzz.blacklanternsecurity.com:8080/x"}))

        module_test.blasthttp_mock.add_callback(flaky_page, url=f"{index}&page=1")

    def check(self, module_test, events):
        names = {e.data: e for e in events if e.type == "DNS_NAME" and str(e.module) == "commoncrawl"}
        assert "asdf.blacklanternsecurity.com" in names, "Failed to detect subdomain"
        assert "zzzz.blacklanternsecurity.com" in names, "Failed to retry a flaky index page"
        assert module_test.page1_requests == 2
        assert "CC-MAIN-2026-43" in names["asdf.blacklanternsecurity.com"].discovery_context
