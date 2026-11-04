import time
import asyncio

from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey
from bbot.core.config.models import BaseModuleConfig, Field


class virustotal(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["safe", "subdomain-enum", "passive"]
    meta = {
        "freshness": "historical",
        "description": "Query VirusTotal's API for subdomains",
        "created_date": "2022-08-25",
        "author": "@TheTechromancer",
    }

    class Config(BaseModuleConfig):
        api_key: str | list[str] = Field("", description="VirusTotal API Key", sensitive=True, mandatory=True)
        requests_per_minute: int = Field(4, description="Max API requests per minute (Public API allows 4)")
        max_pages: int = Field(
            25,
            description="Max result pages per domain, 40 subdomains each (0 = no limit). Public API allows 500 requests/day",
        )

    base_url = "https://www.virustotal.com/api/v3"
    # max page size for the relationships endpoint
    page_size = 40

    async def setup(self):
        self._request_lock = asyncio.Lock()
        self._last_request_time = 0
        return await super().setup()

    def make_url(self, query):
        return f"{self.base_url}/domains/{self.helpers.quote(query)}/subdomains?limit={self.page_size}"

    def prepare_api_request(self, url, kwargs):
        kwargs["headers"]["x-apikey"] = self.api_key
        return url, kwargs

    async def api_request(self, *args, **kwargs):
        # space requests out evenly instead of bursting into the per-minute quota and sleeping on 429s
        async with self._request_lock:
            interval = 60 / max(1, self.config.get("requests_per_minute", 4))
            wait = self._last_request_time + interval - time.time()
            if wait > 0:
                await self.helpers.sleep(wait)
            self._last_request_time = time.time()
        return await super().api_request(*args, **kwargs)

    async def handle_event(self, event):
        await self.handle_event_paginated(event)

    async def query_paginated(self, query):
        url = self.make_url(query)
        max_pages = self.config.get("max_pages", 25)
        pages = 0
        while url:
            r = await self.api_request(url)
            if r is None:
                break
            subdomains = await self.parse_results(r, query)
            self.verbose(f'Got {len(subdomains):,} subdomains for "{query}" (page {pages + 1})')
            if not subdomains:
                break
            yield subdomains
            pages += 1
            if max_pages and pages >= max_pages:
                self.verbose(f'Stopping at max_pages={max_pages} for "{query}"')
                break
            try:
                url = r.json().get("links", {}).get("next", "")
            except Exception:
                break

    async def parse_results(self, r, query):
        text = getattr(r, "text", "")
        return await self.scan.extract_in_scope_hostnames(text)
