from .base import ModuleTestBase


class TestCriminalIP(ModuleTestBase):
    config_overrides = {"modules": {"criminalip": {"api_key": "asdf"}}, "scope": {"report_distance": 1}}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["127.0.0.1"]},
                "asdf.blacklanternsecurity.com": {"A": ["127.0.0.1"]},
                "zzzz.blacklanternsecurity.com": {"A": ["127.0.0.1"]},
                "evilcorp-cdn.com": {"A": ["127.0.0.2"]},
            }
        )

    async def setup_before_prep(self, module_test):
        headers = {"x-api-key": "asdf"}
        module_test.blasthttp_mock.add_response(
            url="https://api.criminalip.io/v1/domain/reports?query=example.com&offset=0",
            match_headers=headers,
            json={"status": 200, "message": "api success", "data": {"count": 0, "reports": []}},
        )
        module_test.blasthttp_mock.add_response(
            url="https://api.criminalip.io/v1/domain/reports?query=blacklanternsecurity.com&offset=0",
            match_headers=headers,
            json={
                "status": 200,
                "message": "api success",
                "data": {
                    "count": 2,
                    "reports": [
                        {"scan_id": "111", "reg_dtime": "2025-01-01 00:00:00"},
                        {"scan_id": "222", "reg_dtime": "2026-09-07 05:15:05"},
                    ],
                },
            },
        )
        module_test.blasthttp_mock.add_response(
            url="https://api.criminalip.io/v2/domain/report/222",
            match_headers=headers,
            json={
                "status": 200,
                "message": "api success",
                "data": {
                    "subdomains": [{"subdomain_name": "asdf.blacklanternsecurity.com"}],
                    "connected_domain_subdomain": [
                        {
                            "main_domain": {"domain": "blacklanternsecurity.com"},
                            "subdomains": [{"domain": "zzzz.blacklanternsecurity.com"}],
                        },
                        {"main_domain": {"domain": "evilcorp-cdn.com"}, "subdomains": []},
                    ],
                    "connected_ip": [{"ip": "1.2.3.4", "score": "safe"}],
                },
            },
        )

    def check(self, module_test, events):
        names = {e.data: e for e in events if e.type == "DNS_NAME" and str(e.module) == "criminalip"}
        assert "asdf.blacklanternsecurity.com" in names, "Failed to detect subdomain"
        assert "zzzz.blacklanternsecurity.com" in names, "Failed to detect connected subdomain"
        assert "222 (2026-09-07)" in names["asdf.blacklanternsecurity.com"].discovery_context, "Newest report not used"
        assert "evilcorp-cdn.com" in names, "Failed to detect connected domain"
        assert "affiliate" in names["evilcorp-cdn.com"].tags
        assert not any(str(e.module) == "criminalip" and e.type == "IP_ADDRESS" for e in events)
