import re

from .base import ModuleTestBase


class TestFofa(ModuleTestBase):
    targets = ["blacklanternsecurity.com", "1.2.3.4"]
    config_overrides = {"modules": {"fofa": {"api_key": "asdf"}}}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                "asdf.blacklanternsecurity.com": {"A": ["1.2.3.4"]},
            }
        )

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
                    ["https://asdf.blacklanternsecurity.com:8443", "1.2.3.4", "8443"],
                    ["1.2.3.4:22", "1.2.3.4", "22"],
                ],
            },
        )
        module_test.blasthttp_mock.add_response(
            url="https://fofa.info/api/v1/host/1.2.3.4?detail=true&key=asdf",
            json={
                "error": False,
                "ports": [{"port": 8080, "products": [{"product": "nginx"}]}],
            },
        )

    def check(self, module_test, events):
        assert any(e.type == "DNS_NAME" and e.data == "asdf.blacklanternsecurity.com" for e in events), (
            "Failed to detect subdomain"
        )
        assert any(e.type == "OPEN_TCP_PORT" and e.data == "asdf.blacklanternsecurity.com:8443" for e in events), (
            "Failed to detect open port on hostname"
        )
        assert any(e.type == "OPEN_TCP_PORT" and e.data == "1.2.3.4:8080" for e in events), (
            "Failed to detect open port from host details"
        )
        assert any(e.type == "TECHNOLOGY" and e.data["technology"] == "nginx" for e in events), (
            "Failed to detect technology"
        )
        # ports must be attached to the host they were observed on, not to the queried domain
        assert not any(e.type == "OPEN_TCP_PORT" and e.data == "blacklanternsecurity.com:8080" for e in events)
