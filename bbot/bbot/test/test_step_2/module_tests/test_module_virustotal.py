from .base import ModuleTestBase


base_url = "https://www.virustotal.com/api/v3/domains/blacklanternsecurity.com/subdomains"


def subdomains_page(hostname, next_url=None):
    links = {"self": f"{base_url}?limit=40"}
    if next_url:
        links["next"] = next_url
    return {
        "meta": {"count": 2},
        "data": [
            {
                "attributes": {
                    "last_dns_records": [{"type": "A", "value": "168.62.180.225", "ttl": 3600}],
                    "last_dns_records_date": 1657734301,
                },
                "type": "domain",
                "id": hostname,
                "links": {"self": f"https://www.virustotal.com/api/v3/domains/{hostname}"},
            }
        ],
        "links": links,
    }


class TestVirusTotal(ModuleTestBase):
    config_overrides = {"modules": {"virustotal": {"api_key": "asdf", "requests_per_minute": 6000}}}

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url=f"{base_url}?limit=40",
            match_headers={"x-apikey": "asdf"},
            json=subdomains_page("asdf.blacklanternsecurity.com", next_url=f"{base_url}?cursor=abc&limit=40"),
        )
        module_test.blasthttp_mock.add_response(
            url=f"{base_url}?cursor=abc&limit=40",
            match_headers={"x-apikey": "asdf"},
            json=subdomains_page("zzzz.blacklanternsecurity.com"),
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert any(e.data == "zzzz.blacklanternsecurity.com" for e in events), "Failed to follow pagination"


class TestVirusTotal_MaxPages(TestVirusTotal):
    module_name = "virustotal"
    config_overrides = {"modules": {"virustotal": {"api_key": "asdf", "requests_per_minute": 6000, "max_pages": 1}}}

    def check(self, module_test, events):
        assert any(e.data == "asdf.blacklanternsecurity.com" for e in events), "Failed to detect subdomain"
        assert not any(e.data == "zzzz.blacklanternsecurity.com" for e in events), "max_pages was not respected"
