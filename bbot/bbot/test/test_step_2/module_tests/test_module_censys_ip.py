from .base import ModuleTestBase


host_url = "https://api.platform.censys.io/v3/global/asset/host"
auth_headers = {"Authorization": "Bearer asdf"}


def host_response(ip, services, dns=None):
    return {"result": {"resource": {"ip": ip, "services": services, "dns": dns or {}}}}


class TestCensys_IP(ModuleTestBase):
    targets = ["1.2.3.4"]
    config_overrides = {"modules": {"censys_ip": {"api_key": "asdf"}}}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                "wildcard.evilcorp.com": {"A": ["1.2.3.4"]},
                "certname.evilcorp.com": {"A": ["1.2.3.4"]},
                "certsubject.evilcorp.com": {"A": ["1.2.3.4"]},
                "reversedns.evilcorp.com": {"A": ["1.2.3.4"]},
                "ptr.evilcorp.com": {"A": ["1.2.3.4"]},
            }
        )

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url=f"{host_url}/1.2.3.4",
            match_headers=auth_headers,
            json=host_response(
                "1.2.3.4",
                [
                    {"port": 53, "protocol": "DNS", "transport_protocol": "udp", "scan_time": "2026-10-30T19:02:50Z"},
                    {
                        "port": 22,
                        "protocol": "SSH",
                        "transport_protocol": "tcp",
                        "software": [{"product": "openssh", "cpe": "cpe:2.3:a:openbsd:openssh:8.9"}],
                    },
                    {
                        "port": 80,
                        "protocol": "HTTP",
                        "transport_protocol": "tcp",
                        "endpoints": [{"endpoint_type": "HTTP", "http": {"uri": "http://1.2.3.4/"}}],
                    },
                    {
                        "port": 443,
                        "protocol": "HTTP",
                        "transport_protocol": "tcp",
                        "endpoints": [{"endpoint_type": "HTTP", "http": {"uri": "https://1.2.3.4/"}}],
                        "cert": {
                            "names": ["*.wildcard.evilcorp.com", "certname.evilcorp.com"],
                            "parsed": {"subject": {"common_name": ["certsubject.evilcorp.com"]}},
                        },
                        "software": [{"product": "java"}],
                    },
                    {
                        "port": 8443,
                        "protocol": "HTTP",
                        "transport_protocol": "tcp",
                        "endpoints": [{"endpoint_type": "HTTP", "http": {"uri": "https://1.2.3.4:8443/admin"}}],
                    },
                    {"port": 443, "protocol": "UNKNOWN", "transport_protocol": "quic"},
                ],
                dns={
                    "names": ["reversedns.evilcorp.com", "ptr.evilcorp.com"],
                    "reverse_dns": {"names": ["ptr.evilcorp.com"], "resolve_time": "2026-10-28T14:11:33Z"},
                },
            ),
        )

    def check(self, module_test, events):
        ports = {(e.type, e.data): e for e in events if e.type in ("OPEN_TCP_PORT", "OPEN_UDP_PORT")}
        for expected in (
            ("OPEN_UDP_PORT", "1.2.3.4:53"),
            ("OPEN_TCP_PORT", "1.2.3.4:22"),
            ("OPEN_TCP_PORT", "1.2.3.4:80"),
            ("OPEN_TCP_PORT", "1.2.3.4:443"),
            ("OPEN_TCP_PORT", "1.2.3.4:8443"),
            ("OPEN_UDP_PORT", "1.2.3.4:443"),
        ):
            assert expected in ports, f"Failed to detect {expected}"
        assert "scanned 2026-10-30" in ports[("OPEN_UDP_PORT", "1.2.3.4:53")].discovery_context

        for url in ("http://1.2.3.4/", "https://1.2.3.4/", "https://1.2.3.4:8443/admin"):
            assert any(e.type == "URL_UNVERIFIED" and e.url == url for e in events), f"Failed to detect URL {url}"

        for name in (
            "wildcard.evilcorp.com",
            "certname.evilcorp.com",
            "certsubject.evilcorp.com",
            "reversedns.evilcorp.com",
            "ptr.evilcorp.com",
        ):
            assert any(e.type == "DNS_NAME" and e.data == name for e in events), f"Failed to detect {name}"

        assert any(e.type == "TECHNOLOGY" and e.data["technology"] == "cpe:2.3:a:openbsd:openssh:8.9" for e in events)
        assert any(e.type == "TECHNOLOGY" and e.data["technology"] == "java" for e in events)
        assert not any(e.type == "PROTOCOL" and e.data["protocol"] in ("HTTP", "HTTPS") for e in events)
        assert any(e.type == "PROTOCOL" and e.data["protocol"] == "DNS" for e in events)
        assert any(e.type == "PROTOCOL" and e.data["protocol"] == "SSH" for e in events)
        assert any(e.type == "PROTOCOL" and e.data["protocol"] == "QUIC" for e in events)


class TestCensys_IP_InScopeOnly(ModuleTestBase):
    """With in_scope_only (the default), out-of-scope IPs are not queried."""

    module_name = "censys_ip"
    targets = ["evilcorp.com"]
    config_overrides = {"modules": {"censys_ip": {"api_key": "asdf"}}}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns({"evilcorp.com": {"A": ["1.1.1.1"]}})

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url=f"{host_url}/1.1.1.1",
            match_headers=auth_headers,
            json=host_response("1.1.1.1", [{"port": 80, "protocol": "HTTP", "transport_protocol": "tcp"}]),
        )

    def check(self, module_test, events):
        assert not any(e.type == "OPEN_TCP_PORT" and "1.1.1.1" in e.data for e in events), (
            "Should not query out-of-scope IPs"
        )


class TestCensys_IP_OutOfScope(TestCensys_IP_InScopeOnly):
    """With in_scope_only disabled, IPs up to distance 1 are queried."""

    config_overrides = {
        "modules": {"censys_ip": {"api_key": "asdf", "in_scope_only": False}},
        "dns": {"minimal": False},
        "scope": {"report_distance": 1},
    }

    def check(self, module_test, events):
        assert any(e.type == "OPEN_TCP_PORT" and e.data == "1.1.1.1:80" for e in events), (
            "Should query out-of-scope IPs when in_scope_only is False"
        )


class TestCensys_IP_Forbidden(ModuleTestBase):
    """A token without access to the endpoint puts the module in error state instead of retrying forever."""

    module_name = "censys_ip"
    targets = ["1.2.3.4", "5.6.7.8"]
    config_overrides = {"modules": {"censys_ip": {"api_key": "asdf"}}}

    async def setup_before_prep(self, module_test):
        for ip in ("1.2.3.4", "5.6.7.8"):
            module_test.blasthttp_mock.add_response(
                url=f"{host_url}/{ip}",
                status_code=403,
                json={"title": "Forbidden", "status": 403, "detail": "Invalid token"},
            )

    def check(self, module_test, events):
        assert not any(str(e.module) == "censys_ip" for e in events)
        assert module_test.scan.modules["censys_ip"].errored
