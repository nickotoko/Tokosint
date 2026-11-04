from .base import ModuleTestBase


def reverse_page(org, names, total=None):
    total = len(names) if total is None else total
    header = [
        ";ASN    : \x1b[38;5;171m64500\x1b[0m [https://bgpview.io/asn/64500]",
        f";Org    : {org}",
        f";;Entries: {len(names)}/{total} [https://ip.thc.org/x?f=abc.co.uk to filter]",
        ";;Rate Limit: You can make 249 requests (Replenishes at 0.50/sec)",
    ]
    return "\n".join(header + names)


class TestTHC(ModuleTestBase):
    targets = ["blacklanternsecurity.com", "1.2.3.4", "5.6.7.8"]
    config_overrides = {"modules": {"thc": {"max_reverse_names": 2}}, "scope": {"report_distance": 1}}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["127.0.0.1"]},
                "asdf.blacklanternsecurity.com": {"A": ["127.0.0.1"]},
                "bls-brand1.com": {"A": ["127.0.0.2"]},
                "bls-brand2.com": {"A": ["127.0.0.2"]},
                "bls-brand3.com": {"A": ["127.0.0.2"]},
            }
        )
        module_test.blasthttp_mock.add_response(
            url="https://ip.thc.org/api/v1/subdomains/download?domain=blacklanternsecurity.com&limit=50000&hide_header=true",
            text="asdf.blacklanternsecurity.com\nunrelated.evilcorp.com\n",
        )
        # own network (owner named like the target): more names allowed than max_reverse_names
        module_test.blasthttp_mock.add_response(
            url="https://ip.thc.org/1.2.3.4?limit=101",
            text=reverse_page("Blacklanternsecurity LLC", ["bls-brand1.com", "bls-brand2.com", "bls-brand3.com"]),
        )
        # shared hosting: too many names and an unrelated owner
        module_test.blasthttp_mock.add_response(
            url="https://ip.thc.org/5.6.7.8?limit=101",
            text=reverse_page("Some Hosting Ltd", ["site1.example.org", "site2.example.org"], total=400),
        )

    def check(self, module_test, events):
        names = {e.data for e in events if e.type == "DNS_NAME" and str(e.module) == "thc"}
        assert "asdf.blacklanternsecurity.com" in names, "Failed to detect subdomain"
        assert "unrelated.evilcorp.com" not in names
        assert {"bls-brand1.com", "bls-brand2.com", "bls-brand3.com"} <= names, "own-network reverse IP failed"
        assert not any(n.endswith("example.org") for n in names), "shared hosting must be ignored"
