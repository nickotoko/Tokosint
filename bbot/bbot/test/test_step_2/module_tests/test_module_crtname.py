from .base import ModuleTestBase


class TestCrtName(ModuleTestBase):
    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["127.0.0.1"]},
                "asdf.blacklanternsecurity.com": {"A": ["127.0.0.1"]},
            }
        )
        module_test.blasthttp_mock.add_response(
            url="https://crt.name/v1/search?apex=blacklanternsecurity.com",
            match_headers={"Accept": "application/json"},
            json=[
                {"sub": "blacklanternsecurity.com"},
                {"sub": "ASDF.blacklanternsecurity.com"},
                {"sub": "unrelated.evilcorp.com"},
            ],
        )

    def check(self, module_test, events):
        names = {e.data for e in events if e.type == "DNS_NAME" and str(e.module) == "crtname"}
        assert names == {"asdf.blacklanternsecurity.com"}, names
