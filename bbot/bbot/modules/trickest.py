from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey
from bbot.core.config.models import BaseModuleConfig, Field


class Trickest(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["safe", "affiliates", "subdomain-enum", "passive"]
    meta = {
        "freshness": "historical",
        "description": "Query Trickest's API for subdomains",
        "author": "@amiremami",
        "created_date": "2024-07-27",
    }

    class Config(BaseModuleConfig):
        api_key: str | list[str] = Field("", description="Trickest API key", sensitive=True, mandatory=True)
        dataset: str = Field("Subdomains", description="Name of the solution dataset to query")

    base_url = "https://api.trickest.io/solutions/v1/public/solution/a7cba1f1-df07-4a5c-876a-953f178996be"
    # max page size accepted by the API
    page_size = 500

    def prepare_api_request(self, url, kwargs):
        kwargs["headers"]["Authorization"] = f"Token {self.api_key}"
        return url, kwargs

    async def ping(self):
        # dataset ids change when Trickest rebuilds the solution, so resolve the id by name
        dataset_name = self.config.get("dataset", "Subdomains")
        r = await self.api_request(f"{self.base_url}/dataset")
        if getattr(r, "status_code", 0) != 200:
            raise ValueError(getattr(r, "text", "no response from server"))
        datasets = {d.get("name"): d.get("id") for d in r.json().get("results", [])}
        self.dataset_id = datasets.get(dataset_name)
        if not self.dataset_id:
            raise ValueError(
                f'Dataset "{dataset_name}" not found (available: {", ".join(sorted(map(str, datasets)))})'
            )

    async def handle_event(self, event):
        await self.handle_event_paginated(event)

    def make_url(self, query):
        url = f"{self.base_url}/view?q=hostname%20~%20%22.{self.helpers.quote(query)}%22"
        url += f"&dataset_id={self.dataset_id}"
        url += "&limit={page_size}&offset={offset}&select=hostname&orderby=hostname"
        return url

    async def parse_results(self, j, query):
        results = j.get("results", [])
        subdomains = set()
        for item in results:
            hostname = item.get("hostname", "")
            if hostname:
                subdomains.add(hostname)
        return subdomains
