import json

from .base import ModuleTestBase


base = (
    "https://arquivo.pt/wayback/cdx?url=blacklanternsecurity.com&matchType=domain&output=json&fields=url%2Ctimestamp"
)


def cdx(*records):
    return "\n".join(json.dumps({"url": url, "timestamp": ts}) for url, ts in records)


class TestArquivo(ModuleTestBase):
    config_overrides = {"modules": {"arquivo": {"max_records": 3}}}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["127.0.0.1"]},
                "asdf.blacklanternsecurity.com": {"A": ["127.0.0.1"]},
                "zzzz.blacklanternsecurity.com": {"A": ["127.0.0.1"]},
            }
        )
        module_test.blasthttp_mock.add_response(
            url=f"{base}&limit=2",
            text=cdx(
                ("http://asdf.blacklanternsecurity.com/", "20180413000000"),
                ("http://asdf.blacklanternsecurity.com/page", "20210101000000"),
            ),
        )

        # page size is shrunk so the test exercises offset pagination and the max_records cap
        module_test.module.page_size = 2
        module_test.blasthttp_mock.add_response(
            url=f"{base}&limit=1&offset=2",
            text=cdx(("https://zzzz.blacklanternsecurity.com/", "20260101000000")),
        )

    def check(self, module_test, events):
        names = {e.data: e for e in events if e.type == "DNS_NAME" and str(e.module) == "arquivo"}
        assert "asdf.blacklanternsecurity.com" in names, "Failed to detect subdomain"
        assert "archived 2018..2021" in names["asdf.blacklanternsecurity.com"].discovery_context
        assert "zzzz.blacklanternsecurity.com" in names, "Failed to follow pagination"
