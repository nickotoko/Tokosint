from .base import ModuleTestBase
from bbot.test.mock_blasthttp import MockResponse


class TestShodan_IDB(ModuleTestBase):
    config_overrides = {"dns": {"minimal": False}}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                "autodiscover.blacklanternsecurity.com": {"A": ["2.3.4.5"]},
                "mail.blacklanternsecurity.com": {"A": ["3.4.5.6"]},
            }
        )

        module_test.blasthttp_mock.add_response(
            url="https://internetdb.shodan.io/1.2.3.4",
            json={
                "cpes": [
                    "cpe:/a:microsoft:internet_information_services",
                    "cpe:/a:microsoft:outlook_web_access:15.0.1367",
                ],
                "hostnames": [
                    "autodiscover.blacklanternsecurity.com",
                    "mail.blacklanternsecurity.com",
                ],
                "ip": "1.2.3.4",
                "ports": [25, 80, 443],
                "tags": ["starttls", "self-signed", "eol-os"],
                "vulns": ["CVE-2021-26857", "CVE-2021-26855"],
            },
        )

        module_test.cvedb_request_counts = {}

        def make_cb(cve_id, cvss):
            def cb(request):
                module_test.cvedb_request_counts[cve_id] = module_test.cvedb_request_counts.get(cve_id, 0) + 1
                return MockResponse(status_code=200, json={"cve_id": cve_id, "cvss_v3": cvss})

            return cb

        module_test.blasthttp_mock.add_callback(
            make_cb("CVE-2021-26857", 7.8), url="https://cvedb.shodan.io/cve/CVE-2021-26857"
        )
        module_test.blasthttp_mock.add_callback(
            make_cb("CVE-2021-26855", 9.1), url="https://cvedb.shodan.io/cve/CVE-2021-26855"
        )

    def check(self, module_test, events):
        assert 8 == len([e for e in events if str(e.module) == "shodan_idb"])
        assert 1 == len(
            [e for e in events if e.type == "DNS_NAME" and e.data == "autodiscover.blacklanternsecurity.com"]
        )
        assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "mail.blacklanternsecurity.com"])
        assert 3 == len(
            [
                e
                for e in events
                if e.type == "OPEN_TCP_PORT" and e.host == "blacklanternsecurity.com" and str(e.module) == "shodan_idb"
            ]
        )
        finding_events = [e for e in events if e.type == "FINDING" and str(e.module) == "shodan_idb"]
        assert 1 == len(finding_events)
        description = finding_events[0].data["description"]
        assert "blacklanternsecurity.com" in description
        assert "CVE-2021-26857 [HIGH, 7.8]" in description
        assert "CVE-2021-26855 [CRITICAL, 9.1]" in description
        assert description.index("CVE-2021-26855") < description.index("CVE-2021-26857")
        assert "\n" not in description
        assert finding_events[0].data["severity"] == "INFO"
        assert 2 == len([e for e in events if e.type == "TECHNOLOGY" and str(e.module) == "shodan_idb"])

        assert set(module_test.module._cve_cache.keys()) == {"CVE-2021-26857", "CVE-2021-26855"}
        assert module_test.cvedb_request_counts == {"CVE-2021-26857": 1, "CVE-2021-26855": 1}


class TestShodan_IDB_CrossHostCache(ModuleTestBase):
    """Same CVE on two different hosts must be fetched from CVEDB only once."""

    module_name = "shodan_idb"
    targets = ["1.2.3.4", "5.6.7.8"]
    config_overrides = {"dns": {"minimal": False}}

    async def setup_after_prep(self, module_test):
        for ip in ("1.2.3.4", "5.6.7.8"):
            module_test.blasthttp_mock.add_response(
                url=f"https://internetdb.shodan.io/{ip}",
                json={"cpes": [], "hostnames": [], "ip": ip, "ports": [443], "tags": [], "vulns": ["CVE-2021-26855"]},
            )
        module_test.cvedb_counts = {}

        def cb(request):
            module_test.cvedb_counts["CVE-2021-26855"] = module_test.cvedb_counts.get("CVE-2021-26855", 0) + 1
            return MockResponse(status_code=200, json={"cve_id": "CVE-2021-26855", "cvss_v3": 9.1})

        module_test.blasthttp_mock.add_callback(cb, url="https://cvedb.shodan.io/cve/CVE-2021-26855")

    def check(self, module_test, events):
        findings = [e for e in events if e.type == "FINDING" and str(e.module) == "shodan_idb"]
        assert len(findings) == 2
        assert module_test.cvedb_counts == {"CVE-2021-26855": 1}


class TestShodan_IDB_ApiKey(ModuleTestBase):
    """With an API key the full host API is used, including historical banner dates."""

    module_name = "shodan_idb"
    targets = ["1.2.3.4", "blacklanternsecurity.com"]
    config_overrides = {"modules": {"shodan_idb": {"api_key": "asdf", "history": True}}}

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="https://api.shodan.io/api-info?key=asdf", json={"plan": "dev", "query_credits": 100}
        )

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "blacklanternsecurity.com": {"A": ["1.2.3.4"]},
                "asdf.blacklanternsecurity.com": {"A": ["1.2.3.4"]},
            }
        )
        module_test.blasthttp_mock.add_response(
            url="https://api.shodan.io/shodan/host/1.2.3.4?history=true&key=asdf",
            json={
                "ip_str": "1.2.3.4",
                "hostnames": ["asdf.blacklanternsecurity.com"],
                "ports": [443],
                "tags": ["cloud"],
                "vulns": ["CVE-2021-26855"],
                "data": [
                    {
                        "port": 443,
                        "transport": "tcp",
                        "timestamp": "2026-08-02T10:00:00.000000",
                        "cpe23": ["cpe:2.3:a:nginx:nginx"],
                    },
                    {"port": 443, "transport": "tcp", "timestamp": "2026-10-30T10:00:00.000000"},
                    {"port": 22, "transport": "tcp", "timestamp": "2026-09-01T10:00:00.000000"},
                    {"port": 53, "transport": "udp", "timestamp": "2026-09-01T10:00:00.000000"},
                ],
            },
        )
        module_test.blasthttp_mock.add_response(
            url="https://cvedb.shodan.io/cve/CVE-2021-26855", json={"cve_id": "CVE-2021-26855", "cvss_v3": 9.1}
        )

    def check(self, module_test, events):
        ports = {e.data: e for e in events if e.type == "OPEN_TCP_PORT" and str(e.module) == "shodan_idb"}
        assert {"1.2.3.4:443", "1.2.3.4:22"} <= set(ports)
        assert not any(p.endswith(":53") for p in ports), "UDP banners must not become TCP ports"
        assert "observed 2026-08-02 .. 2026-10-30" in ports["1.2.3.4:443"].discovery_context
        assert "observed 2026-09-01" in ports["1.2.3.4:22"].discovery_context
        assert any(e.type == "DNS_NAME" and e.data == "asdf.blacklanternsecurity.com" for e in events)
        assert any(e.type == "TECHNOLOGY" and e.data["technology"] == "cpe:2.3:a:nginx:nginx" for e in events)
        assert any(e.type == "FINDING" and "CVE-2021-26855" in e.data["cves"] for e in events)
