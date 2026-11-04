from .base import ModuleTestBase


class TestRelatedDomains(ModuleTestBase):
    module_name = "related_domains"
    config_overrides = {"dns": {"minimal": False}, "scope": {"report_distance": 1}}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {
                    "A": ["127.0.0.1"],
                    "NS": ["ns1.blacklanternsecurity.com."],
                    # mail provider: forward reference only, must not be promoted
                    "MX": ["10 mx.bls-pay.com.", "20 mx.mailprovider.com.", "30 bls-receipts.com."],
                    "TXT": ['"v=spf1 include:_spf.bls-pay.com include:_spf.mailprovider.com ~all"'],
                },
                "ns1.blacklanternsecurity.com": {"A": ["127.0.0.2"]},
                "mx.mailprovider.com": {"A": ["127.0.0.3"]},
                "mailprovider.com": {"A": ["127.0.0.3"], "NS": ["ns.mailprovider.com."]},
                # same organisation: its DNS is served by the target's name server
                "mx.bls-pay.com": {"A": ["127.0.0.4"]},
                "bls-pay.com": {
                    "A": ["127.0.0.4"],
                    "NS": ["ns1.blacklanternsecurity.com."],
                    "MX": ["10 mx.bls-tips.com."],
                },
                "_dmarc.bls-pay.com": {"TXT": ['"v=DMARC1; p=quarantine; rua=mailto:dmarc@blacklanternsecurity.com"']},
                # related only through bls-pay.com (chain): found once bls-pay.com is in scope
                "mx.bls-tips.com": {"A": ["127.0.0.5"]},
                "bls-tips.com": {"A": ["127.0.0.5"], "TXT": ['"v=spf1 include:_spf.bls-pay.com ~all"']},
                # first seen as the bare domain itself (an MX host), not as a subdomain
                "bls-receipts.com": {"A": ["127.0.0.6"], "NS": ["ns1.blacklanternsecurity.com."]},
            }
        )

    def check(self, module_test, events):
        promoted = {e.data: e for e in events if e.type == "DNS_NAME" and str(e.module) == "related_domains"}
        assert set(promoted) == {"bls-pay.com", "bls-tips.com", "bls-receipts.com"}, promoted
        bls_pay = promoted["bls-pay.com"]
        assert bls_pay.scope_distance == 0
        assert {"related-org", "relation-ns", "relation-dmarc", "relation-forward-spf"} <= bls_pay.tags
        assert "relation-spf" in promoted["bls-tips.com"].tags
        assert promoted["bls-receipts.com"].scope_distance == 0
        assert module_test.scan.in_target("www.bls-tips.com")
        assert not module_test.scan.in_target("mailprovider.com")
