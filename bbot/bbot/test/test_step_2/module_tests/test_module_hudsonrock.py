from .base import ModuleTestBase


class TestHudsonRock(ModuleTestBase):
    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["127.0.0.1"]},
                "sso.blacklanternsecurity.com": {"A": ["127.0.0.1"]},
            }
        )
        module_test.blasthttp_mock.add_response(
            url="https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=blacklanternsecurity.com",
            json={
                "total": 12,
                "employees": 2,
                "users": 10,
                "third_parties": 0,
                "last_employee_compromised": "2026-06-09T00:00:00.000Z",
                "last_user_compromised": "2026-10-30T00:00:00.000Z",
                "stealerFamilies": {"total": 12, "Lumma": 10, "RedLine": 2, "Vidar": 0},
                "data": {
                    "all_urls": [
                        {"url": "https://sso.blacklanternsecurity.com/login", "type": "Employee", "occurrence": 2},
                        {"url": "https://•••••.blacklanternsecurity.com/admin", "type": "User", "occurrence": 1},
                    ]
                },
            },
        )

    def check(self, module_test, events):
        mine = [e for e in events if str(e.module) == "hudsonrock"]
        assert any(e.type == "DNS_NAME" and e.data == "sso.blacklanternsecurity.com" for e in mine)
        assert any(e.type == "URL_UNVERIFIED" and e.url == "https://sso.blacklanternsecurity.com/login" for e in mine)
        assert not any("•" in str(e.data) for e in mine), "masked URLs must be skipped"
        findings = [e for e in mine if e.type == "FINDING"]
        assert len(findings) == 1
        description = findings[0].data["description"]
        assert "2 employees (last 2026-06-09)" in description
        assert "Lumma (10)" in description and "Vidar" not in description
