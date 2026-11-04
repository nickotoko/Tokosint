from bbot.modules.templates.subdomain_enum import subdomain_enum
from bbot.core.config.models import BaseModuleConfig, Field


class urlscan(subdomain_enum):
    flags = ["safe", "subdomain-enum", "passive"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME", "URL_UNVERIFIED"]
    meta = {
        "freshness": "historical",
        "description": "Query urlscan.io for subdomains",
        "created_date": "2022-06-09",
        "author": "@TheTechromancer",
    }

    class Config(BaseModuleConfig):
        urls: bool = Field(False, description="Emit URLs in addition to DNS_NAMEs")
        api_key: str | list[str] = Field(
            "", description="urlscan.io API key (optional, raises search quotas)", sensitive=True
        )
        size: int = Field(100, description="Max results per search (the allowed maximum depends on the API key)")

    base_url = "https://urlscan.io/api/v1"
    ping_url = f"{base_url}/quotas"

    async def setup(self):
        self.urls = self.config.get("urls", False)
        if self.config.get("api_key", ""):
            ready, reason = await self.require_api_key()
            if not ready:
                return ready, reason
        return await super().setup()

    def prepare_api_request(self, url, kwargs):
        if self.api_key:
            kwargs["headers"]["API-Key"] = self.api_key
        return url, kwargs

    async def handle_event(self, event):
        query = self.make_query(event)
        for domain, url in await self.query(query):
            parent_event = event
            if domain and domain != query:
                domain_event = self.make_event(domain, "DNS_NAME", parent=event)
                if domain_event:
                    if str(domain_event.host).endswith(query) and not str(domain_event.host) == str(event.host):
                        await self.emit_event(
                            domain_event,
                            abort_if=self.abort_if,
                            context=f'{{module}} searched urlscan.io API for "{query}" and found {{event.type}}: {{event.pretty_string}}',
                        )
                        parent_event = domain_event
            if url:
                url_event = self.make_event(url, "URL_UNVERIFIED", parent=parent_event)
                if url_event:
                    if str(url_event.host).endswith(query):
                        if self.urls:
                            await self.emit_event(
                                url_event,
                                abort_if=self.abort_if,
                                context=f'{{module}} searched urlscan.io API for "{query}" and found {{event.type}}: {{event.pretty_string}}',
                            )
                        else:
                            await self.emit_event(
                                str(url_event.host),
                                "DNS_NAME",
                                parent=event,
                                abort_if=self.abort_if,
                                context=f'{{module}} searched urlscan.io API for "{query}" and found {{event.type}}: {{event.pretty_string}}',
                            )
                    else:
                        self.debug(f"{url_event.host} does not match {query}")

    async def query(self, query):
        results = set()
        url = f"{self.base_url}/search/?q={self.helpers.quote(query)}&size={self.config.get('size', 100)}"
        r = await self.api_request(url)
        try:
            json = r.json()
            if json and type(json) == dict:
                for result in json.get("results", []):
                    if result and type(result) == dict:
                        task = result.get("task", {})
                        if task and type(task) == dict:
                            domain = task.get("domain", "")
                            url = task.get("url", "")
                            if domain or url:
                                results.add((domain, url))
                        page = result.get("page", {})
                        if page and type(page) == dict:
                            domain = page.get("domain", "")
                            url = page.get("url", "")
                            if domain or url:
                                results.add((domain, url))
            else:
                self.debug(f'No results for "{query}"')
        except Exception:
            self.verbose("Error retrieving urlscan results")
        return results
