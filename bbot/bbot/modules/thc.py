import re

from bbot.modules.base import BaseModule
from bbot.modules.templates.shared_hosting import SharedHostingConfig, shared_hosting_filter
from bbot.core.config.models import Field


class thc(shared_hosting_filter, BaseModule):
    """
    Query ip.thc.org (The Hacker's Choice):

    - DNS_NAME -> subdomains of the domain
    - IP_ADDRESS -> domains hosted on the IP (skipped for shared hosting, see shared_hosting_filter)

    No key required; rate limit is a bucket of 250 requests replenishing at 0.5/s. https://ip.thc.org/docs
    """

    watched_events = ["DNS_NAME", "IP_ADDRESS"]
    produced_events = ["DNS_NAME"]
    flags = ["safe", "passive", "subdomain-enum", "affiliates"]
    meta = {
        "freshness": "historical",
        "description": "Query ip.thc.org for subdomains and for domains hosted on an IP",
        "created_date": "2026-11-01",
        "author": "@nickotoko",
    }

    class Config(SharedHostingConfig):
        max_subdomains: int = Field(50000, description="Maximum number of subdomains to fetch per domain")

    # IPs of in-scope hosts sit one hop out; reverse lookups need to see them
    scope_distance_modifier = 1

    base_url = "https://ip.thc.org"
    ansi_regex = re.compile(r"\x1b\[[0-9;]*m")
    header_regex = re.compile(r"^;+\s*([A-Za-z ]+?)\s*:\s*(.*)$")

    async def filter_event(self, event):
        if event.type == "DNS_NAME":
            # subdomain lookups only for in-scope names, once per domain; the extra hop is for IPs
            if event.scope_distance > self.scan.scope_search_distance:
                return False, "DNS_NAME is out of scope"
        elif self.is_shared_infrastructure(event):
            return False, "IP belongs to a CDN / cloud provider (shared hosting)"
        return True

    def _incoming_dedup_hash(self, event):
        if event.type == "DNS_NAME":
            return hash(self.helpers.split_domain(event.data)[1]), "per domain"
        return hash(event.data), ""

    async def handle_event(self, event):
        if event.type == "DNS_NAME":
            await self.handle_domain(event)
        else:
            await self.handle_ip(event)

    async def handle_domain(self, event):
        _, domain = self.helpers.split_domain(event.data)
        self.remember_org_name(domain)
        params = {"domain": domain, "limit": self.config.get("max_subdomains", 50000), "hide_header": "true"}
        url = self.helpers.add_get_params(f"{self.base_url}/api/v1/subdomains/download", params).geturl()
        _, names = await self.query(url)
        for name in names:
            if name.endswith(f".{domain}") and name != event.data:
                await self.emit_event(
                    name,
                    "DNS_NAME",
                    parent=event,
                    context=f'{{module}} searched ip.thc.org for subdomains of "{domain}" and found {{event.type}}: {{event.pretty_string}}',
                )

    async def handle_ip(self, event):
        limit = max(self.config.get("max_reverse_names", 10), self.config.get("own_network_max_reverse_names", 100))
        header, names = await self.query(f"{self.base_url}/{event.data}?limit={limit + 1}")
        total = self._total_entries(header, len(names))
        owner = [header.get("org", ""), header.get("asn", "")]

        async def get_owner():
            return owner

        if not await self.reverse_names_allowed(event.data, total, get_owner):
            return
        for name in names:
            await self.emit_event(
                name,
                "DNS_NAME",
                parent=event,
                context=f"{{module}} found {{event.type}}: {{event.pretty_string}} hosted on {event.data} via ip.thc.org (network: {header.get('org', '?')})",
            )

    @staticmethod
    def _total_entries(header, default):
        # ";;Entries: 13/13 [...]" -> 13
        match = re.match(r"\s*(\d+)\s*/\s*(\d+)", header.get("entries", ""))
        return int(match.group(2)) if match else default

    async def query(self, url):
        """Returns (header fields, hostnames) from ip.thc.org's text output."""
        r = await self.api_request(url)
        header, names = {}, []
        if getattr(r, "status_code", 0) != 200:
            return header, names
        for line in self.ansi_regex.sub("", r.text).splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith(";"):
                match = self.header_regex.match(line)
                if match:
                    header[match.group(1).strip().lower()] = match.group(2).strip()
                continue
            name = line.split()[0].lower().rstrip(".")
            if self.helpers.is_dns_name(name) and name != "subdomain":
                names.append(name)
        return header, names
