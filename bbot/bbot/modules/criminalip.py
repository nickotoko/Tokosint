from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey
from bbot.core.config.models import BaseModuleConfig, Field


class criminalip(subdomain_enum_apikey):
    """
    Read existing Criminal IP domain reports for subdomains and connected domains.

    Only already-existing reports are read. The module never requests a new domain scan
    (/v1/domain/scan), because that makes Criminal IP crawl the target on our behalf.

    API reference: https://www.criminalip.io/developer/api/get-domain-reports
    """

    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["safe", "subdomain-enum", "affiliates", "passive"]
    meta = {
        "freshness": "historical",
        "description": "Query existing Criminal IP domain reports for subdomains and connected domains",
        "created_date": "2026-11-01",
        "author": "@nickotoko",
    }

    class Config(BaseModuleConfig):
        api_key: str | list[str] = Field("", description="Criminal IP API key", sensitive=True, mandatory=True)
        reports: int = Field(1, description="How many of the most recent existing reports to read per domain")

    base_url = "https://api.criminalip.io"
    ping_url = f"{base_url}/v1/domain/reports?query=example.com&offset=0"

    def prepare_api_request(self, url, kwargs):
        kwargs["headers"]["x-api-key"] = self.api_key
        return url, kwargs

    async def handle_event(self, event):
        query = self.make_query(event)
        for report in await self.get_reports(query):
            scan_id, report_time = report.get("scan_id"), (report.get("reg_dtime") or "")[:10]
            data = await self.get_report(scan_id)
            context = f'{{module}} read Criminal IP report {scan_id} ({report_time}) for "{query}" and found {{event.type}}: {{event.pretty_string}}'
            subdomains, connected = self.extract_hostnames(data)
            for hostname in subdomains - {event.data}:
                await self.emit_event(hostname, "DNS_NAME", parent=event, abort_if=self.abort_if, context=context)
            # domains the scanned page connects to (e.g. a company's other brands); out of scope -> affiliates
            for hostname in connected - subdomains - {event.data}:
                await self.emit_event(
                    hostname, "DNS_NAME", parent=event, tags=["affiliate"], context=f"{context} (connected domain)"
                )

    async def get_reports(self, query):
        url = self.helpers.add_get_params(f"{self.base_url}/v1/domain/reports", {"query": query, "offset": 0}).geturl()
        j = self._json(await self.api_request(url))
        reports = (j.get("data") or {}).get("reports") or []
        # newest first
        reports.sort(key=lambda r: r.get("reg_dtime") or "", reverse=True)
        return reports[: self.config.get("reports", 1)]

    async def get_report(self, scan_id):
        if not scan_id:
            return {}
        j = self._json(await self.api_request(f"{self.base_url}/v2/domain/report/{scan_id}"))
        return j.get("data") or {}

    @staticmethod
    def extract_hostnames(data):
        """Returns (subdomains of the scanned domain, connected domains and their subdomains)."""
        subdomains = {item.get("subdomain_name", "") for item in data.get("subdomains") or []}
        connected = set()
        for group in data.get("connected_domain_subdomain") or []:
            connected.add((group.get("main_domain") or {}).get("domain", ""))
            connected.update(item.get("domain", "") for item in group.get("subdomains") or [])

        def clean(hostnames):
            return {h.lower().strip(".") for h in hostnames if h}

        return clean(subdomains), clean(connected)

    def _json(self, r):
        """Criminal IP wraps errors in a 200 response with its own status field."""
        try:
            j = r.json()
        except Exception:
            return {}
        if not isinstance(j, dict) or j.get("status") != 200:
            message = j.get("message", "") if isinstance(j, dict) else ""
            self.verbose(f"Criminal IP API error: {message}")
            return {}
        return j
