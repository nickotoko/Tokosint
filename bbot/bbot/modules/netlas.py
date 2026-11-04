from bbot.modules.templates.subdomain_enum import subdomain_enum
from bbot.core.config.models import BaseModuleConfig, Field


class netlas(subdomain_enum):
    """
    Query the Netlas.io domain database for subdomains.

    Without a key only the first search page (20 domains) is available. With a key (the free
    Community plan gives 50 requests/day and up to 200 results per download) the whole list is
    downloaded. API reference: https://docs.netlas.io/
    """

    flags = ["safe", "subdomain-enum", "passive"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {
        "freshness": "historical",
        "description": "Query the Netlas.io domain database for subdomains",
        "created_date": "2026-11-01",
        "author": "@nickotoko",
    }

    class Config(BaseModuleConfig):
        api_key: str | list[str] = Field(
            "", description="Netlas API key (optional: without it only the first 20 results)", sensitive=True
        )
        max_results: int = Field(200, description="Maximum number of domains to download (Community plan cap: 200)")

    base_url = "https://app.netlas.io/api"

    async def setup(self):
        self.api_key = self.config.get("api_key", "")
        if not self.api_key:
            self.verbose("No API key set, only the first page of results (20 domains) is available")
        return await super().setup()

    def _api_response_is_success(self, r):
        # the daily quota won't reset for hours; retrying (and sleeping on) it is pointless
        return super()._api_response_is_success(r) or self._is_daily_limit(r)

    @staticmethod
    def _is_daily_limit(r):
        if getattr(r, "status_code", 0) != 429:
            return False
        try:
            return r.json().get("type") == "daily_request_limit_exceeded"
        except Exception:
            return False

    def prepare_api_request(self, url, kwargs):
        if self.api_key:
            kwargs["headers"]["Authorization"] = f"Bearer {self.api_key}"
        return url, kwargs

    async def handle_event(self, event):
        query = self.make_query(event)
        for hostname, seen in (await self.query(query)).items():
            if hostname == event.data or not hostname.endswith(f".{query}"):
                continue
            seen_str = f" (seen {seen})" if seen else ""
            await self.emit_event(
                hostname,
                "DNS_NAME",
                parent=event,
                abort_if=self.abort_if,
                context=f'{{module}} searched Netlas for "{query}" and found {{event.type}}: {{event.pretty_string}}{seen_str}',
            )

    async def query(self, query):
        """Returns {hostname: date it was last seen by Netlas}."""
        netlas_query = f"domain:*.{query}"
        if self.api_key:
            rows = await self.download(netlas_query)
        else:
            url = self.helpers.add_get_params(f"{self.base_url}/domains/", {"q": netlas_query, "start": 0}).geturl()
            rows = self._json(await self.api_request(url)).get("items", [])
        results = {}
        for row in rows if isinstance(rows, list) else []:
            data = row.get("data") if isinstance(row, dict) else None
            if isinstance(data, dict) and isinstance(data.get("domain"), str):
                results[data["domain"].lower().rstrip(".")] = (data.get("@timestamp") or "")[:10]
        return results

    async def download(self, netlas_query):
        count_url = self.helpers.add_get_params(f"{self.base_url}/domains_count/", {"q": netlas_query}).geturl()
        count = self._json(await self.api_request(count_url)).get("count", 0)
        size = min(count, self.config.get("max_results", 200))
        if count > size:
            self.verbose(f'Downloading {size:,} of {count:,} Netlas results for "{netlas_query}"')
        if not size:
            return []
        r = await self.api_request(
            f"{self.base_url}/domains/download/",
            method="POST",
            json={"q": netlas_query, "size": size, "fields": ["domain", "@timestamp"], "source_type": "include"},
        )
        try:
            return r.json()
        except Exception:
            return []

    def _json(self, r):
        try:
            j = r.json()
        except Exception:
            return {}
        if isinstance(j, dict) and j.get("detail"):
            self.verbose(f"Netlas: {j['detail']}")
        return j if isinstance(j, dict) else {}
