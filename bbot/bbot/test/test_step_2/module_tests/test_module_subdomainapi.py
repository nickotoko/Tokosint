from .base import ModuleTestBase


class TestSubdomainAPI(ModuleTestBase):
    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["127.0.0.1"]},
                "asdf.blacklanternsecurity.com": {"A": ["127.0.0.1"]},
            }
        )
        module_test.blasthttp_mock.add_response(
            url="https://api.subdomain.app/v1/query?domain=blacklanternsecurity.com",
            json={
                "domain": "blacklanternsecurity.com",
                "count": 2,
                "total": 2,
                "subdomains": ["ASDF.blacklanternsecurity.com", "unrelated.evilcorp.com"],
            },
        )

    def check(self, module_test, events):
        names = {e.data for e in events if e.type == "DNS_NAME" and str(e.module) == "subdomainapi"}
        assert names == {"asdf.blacklanternsecurity.com"}, names
