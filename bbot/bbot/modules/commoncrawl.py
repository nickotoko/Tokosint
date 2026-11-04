import json
from urllib.parse import urlsplit

from bbot.modules.templates.subdomain_enum import subdomain_enum
from bbot.core.config.models import BaseModuleConfig, Field


class commoncrawl(subdomain_enum):
    """
    Query the Common Crawl URL index for hostnames under the target domain.

    API reference: https://index.commoncrawl.org/ (pywb CDX server, one index per crawl)
    """

    flags = ["safe", "subdomain-enum", "passive"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {
        "freshness": "historical",
        "description": "Query the Common Crawl index for subdomains",
        "created_date": "2026-11-01",
        "author": "@nickotoko",
    }

    class Config(BaseModuleConfig):
        crawls: int = Field(2, description="How many of the most recent crawls to search")
        max_pages: int = Field(20, description="Maximum number of index pages to fetch per crawl")
        retries: int = Field(
            4, description="How many times to retry an index page (the index frequently answers 502/504)"
        )

    base_url = "https://index.commoncrawl.org"
    # seconds to wait before each retry; the index is often overloaded
    _retry_delays = (2, 5, 10, 20)

    async def setup(self):
        self._crawl_ids = None
        return await super().setup()

    async def crawl_ids(self):
        """IDs of the most recent crawls, newest first (fetched once per scan)."""
        if self._crawl_ids is None:
            self._crawl_ids = []
            r = await self.fetch(f"{self.base_url}/collinfo.json")
            try:
                collections = r.json()
                self._crawl_ids = [c["id"] for c in collections][: self.config.get("crawls", 2)]
            except Exception as e:
                self.warning(f"Unable to get the list of crawls from Common Crawl: {e}")
        return self._crawl_ids

    async def fetch(self, url):
        """GET with retries on transient errors. Returns the response, or None if it never succeeded."""
        retries = self.config.get("retries", 4)
        r = None
        for attempt in range(retries + 1):
            r = await self.helpers.request(url, timeout=self.http_timeout_infrastructure + 60)
            status_code = getattr(r, "status_code", 0)
            # 404 is the index's answer for "no captures" — final, not transient
            if status_code in (200, 404):
                return r
            if attempt < retries:
                delay = self._retry_delays[min(attempt, len(self._retry_delays) - 1)]
                self.debug(f"Common Crawl returned HTTP {status_code} for {url}, retrying in {delay}s")
                await self.helpers.sleep(delay)
        self.verbose(f"Giving up on {url} after {retries + 1} attempts (HTTP {getattr(r, 'status_code', 0)})")
        return None

    async def handle_event(self, event):
        query = self.make_query(event)
        for hostname, crawl_id in (await self.query(query)).items():
            if hostname == event.data or not hostname.endswith(f".{query}"):
                continue
            await self.emit_event(
                hostname,
                "DNS_NAME",
                parent=event,
                abort_if=self.abort_if,
                context=f'{{module}} searched Common Crawl ({crawl_id}) for "{query}" and found {{event.type}}: {{event.pretty_string}}',
            )

    async def query(self, query):
        """Returns {hostname: id of the newest crawl it was seen in}."""
        hosts = {}
        for crawl_id in await self.crawl_ids():
            index_url = f"{self.base_url}/{crawl_id}-index?url=*.{self.helpers.quote(query)}&output=json&fl=url"
            r = await self.fetch(f"{index_url}&showNumPages=true")
            try:
                num_pages = int(r.json().get("pages", 0)) if r is not None and r.status_code == 200 else 0
            except Exception:
                num_pages = 0
            max_pages = self.config.get("max_pages", 20)
            if num_pages > max_pages:
                self.verbose(f'Only fetching {max_pages:,} of {num_pages:,} index pages for "{query}" in {crawl_id}')
            for page in range(min(num_pages, max_pages)):
                r = await self.fetch(f"{index_url}&page={page}")
                if r is None or r.status_code != 200:
                    continue
                for line in r.text.splitlines():
                    try:
                        hostname = (urlsplit(json.loads(line)["url"]).hostname or "").lower().rstrip(".")
                    except (ValueError, KeyError, TypeError):
                        continue
                    if hostname:
                        hosts.setdefault(hostname, crawl_id)
        return hosts
