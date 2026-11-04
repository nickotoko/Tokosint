from bbot.modules.templates.subdomain_enum import subdomain_enum


class subdomainapi(subdomain_enum):
    """
    Query subdomain.app, a free subdomain index (no key, no signup). https://subdomain.app/
    """

    flags = ["safe", "subdomain-enum", "passive"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {
        "freshness": "historical",
        "description": "Query subdomain.app's subdomain index",
        "created_date": "2026-11-01",
        "author": "@nickotoko",
    }

    base_url = "https://api.subdomain.app/v1/query"

    def make_url(self, query):
        return f"{self.base_url}?domain={self.helpers.quote(query)}"

    async def parse_results(self, r, query):
        json = r.json()
        if not isinstance(json, dict):
            return set()
        return {str(s).lower() for s in json.get("subdomains") or [] if s}
