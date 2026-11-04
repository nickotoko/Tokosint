import json
from urllib.parse import urlsplit

from bbot.modules.templates.subdomain_enum import subdomain_enum
from bbot.core.config.models import BaseModuleConfig, Field


class arquivo(subdomain_enum):
    """
    Query the CDX index of Arquivo.pt, the Portuguese national web archive (independent of the Internet Archive).

    API reference: https://github.com/arquivo/pwa-technologies/wiki/URL-search:-CDX-server-API
    """

    flags = ["safe", "subdomain-enum", "passive"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {
        "description": "Query the Arquivo.pt web archive for subdomains",
        "created_date": "2026-11-01",
        "author": "@nickotoko",
    }

    class Config(BaseModuleConfig):
        max_records: int = Field(50000, description="Maximum number of archived URLs to fetch per domain")

    base_url = "https://arquivo.pt/wayback/cdx"
    page_size = 10000

    async def handle_event(self, event):
        query = self.make_query(event)
        for hostname, (first, last) in (await self.query(query)).items():
            if hostname == event.data or not hostname.endswith(f".{query}"):
                continue
            seen = first[:4] if first[:4] == last[:4] else f"{first[:4]}..{last[:4]}"
            await self.emit_event(
                hostname,
                "DNS_NAME",
                parent=event,
                abort_if=self.abort_if,
                context=f'{{module}} searched Arquivo.pt for "{query}" and found {{event.type}}: {{event.pretty_string}} (archived {seen})',
            )

    async def query(self, query):
        """Returns {hostname: (first_timestamp, last_timestamp)} for every archived host under the domain."""
        hosts = {}
        max_records = self.config.get("max_records", 50000)
        offset = 0
        while offset < max_records:
            limit = min(self.page_size, max_records - offset)
            params = {"url": query, "matchType": "domain", "output": "json", "fields": "url,timestamp", "limit": limit}
            if offset:
                params["offset"] = offset
            url = self.helpers.add_get_params(self.base_url, params).geturl()
            r = await self.api_request(url, timeout=self.http_timeout_infrastructure + 60)
            if r is None or getattr(r, "status_code", 0) != 200:
                self.verbose(f'Arquivo.pt request for "{query}" failed (status {getattr(r, "status_code", 0)})')
                break
            records = 0
            for line in r.text.splitlines():
                try:
                    item = json.loads(line)
                    hostname = (urlsplit(item["url"]).hostname or "").lower().rstrip(".")
                    timestamp = str(item.get("timestamp", ""))
                except (ValueError, KeyError, TypeError):
                    continue
                records += 1
                if hostname:
                    first, last = hosts.get(hostname, (timestamp, timestamp))
                    hosts[hostname] = (min(first, timestamp), max(last, timestamp))
            if records < limit:
                break
            offset += records
        return hosts
