from .base import ModuleTestBase

BLS = "blacklanternsecurity.com"

# AS of each test address (what asndb would answer)
ASN = {
    "1.1.1.10": {"asn": 200449, "name": "HLL-AS", "description": "HLL LLC"},  # anti-DDoS proxy (Qrator)
    "3.3.3.3": {"asn": 29470, "name": "RETNRU-MSK-AS", "description": "JSC RetnNet"},  # ISP, PTR into the target
    "4.4.4.4": {"asn": 200350, "name": "YandexCloud", "description": "Yandex.Cloud LLC"},  # rented cloud VM
    "5.5.5.5": {"asn": 64500, "name": "BLACKLANTERNSECURITY-AS", "description": "Black Lantern Security"},  # own AS
    "6.6.6.6": {"asn": 3356, "name": "LEVEL3", "description": "Level 3 Parent, LLC"},  # unknown carrier
    "8.8.4.4": {"asn": 2635, "name": "AUTOMATTIC", "description": "Automattic, Inc"},  # WordPress.com hosting
}


class TestIPOwner(ModuleTestBase):
    module_name = "ipowner"
    modules_overrides = []
    # distance 2: the address of the DNS provider's name (NS of the target) reaches the output
    config_overrides = {"dns": {"minimal": False, "search_distance": 2}, "scope": {"report_distance": 2}}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                BLS: {"A": ["1.1.1.10"], "NS": ["ns1.dnsprovider.io."]},
                "ns1.dnsprovider.io": {"A": ["7.7.7.7"]},
                f"blog.{BLS}": {"A": ["8.8.4.4"]},
                # the site is hosted by a provider: the name is a CNAME to its domain
                f"static.{BLS}": {"CNAME": ["static.provider-cdn.net"], "A": ["2.2.2.2"]},
                "static.provider-cdn.net": {"A": ["2.2.2.2"]},
                f"mx.{BLS}": {"A": ["3.3.3.3"]},
                "3.3.3.3.in-addr.arpa": {"PTR": [f"mx.{BLS}"]},
                f"vm.{BLS}": {"A": ["4.4.4.4"]},
                f"own.{BLS}": {"A": ["5.5.5.5"]},
                f"isp.{BLS}": {"A": ["6.6.6.6"]},
            }
        )
        from bbot.modules.base import BaseModule

        class names(BaseModule):
            _name = "names"
            watched_events = ["DNS_NAME"]
            meta = {"freshness": "current"}

            async def handle_event(self, event):
                if event.data == BLS:
                    for sub in ("static", "mx", "vm", "own", "isp", "blog"):
                        await self.emit_event(f"{sub}.{BLS}", "DNS_NAME", parent=event, context="name {event.data}")

        module = names(module_test.scan)
        await module.setup()
        module_test.scan.modules["names"] = module

        self.asn_queries = []

        async def ip_to_subnets(ip):
            self.asn_queries.append(ip)
            info = ASN.get(str(ip))
            return dict(info, subnets=[], country="") if info else module_test.scan.helpers.asn.UNKNOWN_ASN

        module_test.monkeypatch.setattr(module_test.scan.helpers.asn, "ip_to_subnets", ip_to_subnets)

    def check(self, module_test, events):
        ips = {}
        for e in events:
            if e.type == "IP_ADDRESS":
                ips.setdefault(e.data, set()).update(e.tags)

        # anti-DDoS network: the proxy front, third-party
        assert {"ip-proxy", "third-party", "ip-provider-hll-as", "validity-valid"} <= ips["1.1.1.10"]
        # behind a CNAME to a foreign domain: the provider's address, no AS lookup needed
        assert {"ip-proxy", "third-party", "ip-provider-provider-cdn-net"} <= ips["2.2.2.2"], ips["2.2.2.2"]
        assert "2.2.2.2" not in self.asn_queries
        # PTR into the target: own address, even in a carrier's AS
        assert "ip-owner-target" in ips["3.3.3.3"] and "third-party" not in ips["3.3.3.3"]
        # a cloud VM may be the target's own: marked, but not third-party
        assert {"ip-hosting", "ip-provider-yandexcloud"} <= ips["4.4.4.4"]
        assert "third-party" not in ips["4.4.4.4"]
        # AS named after the target
        assert "ip-owner-target" in ips["5.5.5.5"]
        # the address of an out-of-scope name (the target's DNS provider): the provider's
        assert {"ip-proxy", "third-party", "ip-provider-dnsprovider-io"} <= ips["7.7.7.7"], ips["7.7.7.7"]
        # a site builder / SaaS hosting network
        assert {"ip-proxy", "third-party", "ip-provider-automattic"} <= ips["8.8.4.4"], ips["8.8.4.4"]
        # nothing known: no verdict
        assert not {t for t in ips["6.6.6.6"] if t.startswith("ip-")} - {"ipv4"}
        assert "third-party" not in ips["6.6.6.6"]


class TestIPOwner_TargetIP(ModuleTestBase):
    """An IP given as a target is the target's by definition: never classified, never asked about."""

    targets = ["1.1.1.10"]
    module_name = "ipowner"
    modules_overrides = []

    async def setup_after_prep(self, module_test):
        async def ip_to_subnets(ip):
            raise AssertionError("a target IP must not be looked up")

        module_test.monkeypatch.setattr(module_test.scan.helpers.asn, "ip_to_subnets", ip_to_subnets)

    def check(self, module_test, events):
        ip = next(e for e in events if e.type == "IP_ADDRESS" and e.data == "1.1.1.10")
        assert not {"ip-proxy", "ip-hosting", "ip-owner-target", "third-party"} & set(ip.tags)
