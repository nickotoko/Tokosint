from .base import ModuleTestBase


class TestShodanCT(ModuleTestBase):
    config_overrides = {"modules": {"shodanct": {"max_shared_sans": 3}}, "scope": {"report_distance": 1}}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["127.0.0.1"]},
                "asdf.blacklanternsecurity.com": {"A": ["127.0.0.1"]},
                "zzzz.blacklanternsecurity.com": {"A": ["127.0.0.1"]},
                "bls-brand.com": {"A": ["127.0.0.2"]},
                "unrelated1.com": {"A": ["127.0.0.3"]},
            }
        )
        module_test.blasthttp_mock.add_response(
            url="https://ctl.shodan.io/api/v1/domain/blacklanternsecurity.com",
            json=[
                {
                    "hash": "aa",
                    "subject_cn": "*.blacklanternsecurity.com",
                    "issuer_cn": "R11",
                    "not_before": 1788958952,
                    "not_after": 1796734952,
                    "san_dns_names": ["*.asdf.blacklanternsecurity.com", "bls-brand.com"],
                },
                # a shared certificate: its other names must not become affiliates
                {
                    "hash": "bb",
                    "subject_cn": "sni.cdn.example",
                    "issuer_cn": "CDN CA",
                    "not_before": 1788958952,
                    "not_after": 1796734952,
                    "san_dns_names": [
                        "zzzz.blacklanternsecurity.com",
                        "unrelated1.com",
                        "unrelated2.com",
                        "unrelated3.com",
                    ],
                },
            ],
        )

    def check(self, module_test, events):
        names = {e.data: e for e in events if e.type == "DNS_NAME" and str(e.module) == "shodanct"}
        assert "asdf.blacklanternsecurity.com" in names, "Failed to detect subdomain"
        assert "zzzz.blacklanternsecurity.com" in names, "Subdomains from shared certs are still subdomains"
        assert "bls-brand.com" in names and "affiliate" in names["bls-brand.com"].tags, (
            "Failed to detect co-hosted domain"
        )
        assert "unrelated1.com" not in names, "Names from shared certificates must be ignored"
        assert "R11 (2026-09-" in names["asdf.blacklanternsecurity.com"].discovery_context
