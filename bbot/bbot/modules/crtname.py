from bbot.modules.templates.subdomain_enum import subdomain_enum


class crtname(subdomain_enum):
    """
    Query crt.name, a subdomain index built from certificate transparency logs plus historical names.

    Free, no key, 100 requests per IP per day (x-ratelimit-* headers). https://crt.name/
    """

    flags = ["safe", "subdomain-enum", "passive"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {
        "freshness": "historical",
        "description": "Query crt.name's certificate transparency index for subdomains",
        "created_date": "2026-11-01",
        "author": "@nickotoko",
    }

    base_url = "https://crt.name/v1/search"

    async def request_url(self, query):
        url = f"{self.base_url}?apex={self.helpers.quote(query)}"
        return await self.api_request(url, headers={"Accept": "application/json"})

    async def parse_results(self, r, query):
        results = set()
        json = r.json()
        if isinstance(json, list):
            for item in json:
                if isinstance(item, dict) and item.get("sub"):
                    results.add(item["sub"].lower())
        return results
