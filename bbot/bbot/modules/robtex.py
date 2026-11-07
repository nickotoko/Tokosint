import json
import time
import asyncio

from bbot.modules.base import BaseModule
from bbot.modules.templates.shared_hosting import SharedHostingConfig, shared_hosting_filter
from bbot.core.config.models import Field


class robtex(shared_hosting_filter, BaseModule):
    """
    Query Robtex's free passive DNS API.

    - DNS_NAME -> forward pDNS: IPs, name servers, mail servers and CNAMEs the name has pointed to
    - IP_ADDRESS -> reverse pDNS: names that have pointed to the IP (skipped for shared hosting, see below)

    Every record has first/last observation times; records not seen recently are tagged pdns-historical.
    Free API, no key: https://freeapi.robtex.com
    """

    watched_events = ["DNS_NAME", "IP_ADDRESS"]
    produced_events = ["DNS_NAME", "IP_ADDRESS"]
    flags = ["safe", "passive", "subdomain-enum", "affiliates"]
    meta = {
        "freshness": "historical",
        "description": "Query Robtex passive DNS for historical records of names and IPs",
        "created_date": "2026-11-01",
        "author": "@nickotoko",
    }

    class Config(SharedHostingConfig):
        historical_days: int = Field(90, description="Records not seen for this many days are tagged pdns-historical")
        requests_per_minute: int = Field(30, description="Max requests per minute to the free API")

    # IPs of in-scope hosts sit one hop out; reverse lookups need to see them
    scope_distance_modifier = 1

    base_url = "https://freeapi.robtex.com"

    def prepare_api_request(self, url, kwargs):
        # Cloudflare in front of the API challenges browser user-agents that don't come from a real browser,
        # but lets an honest client name through
        kwargs["headers"]["User-Agent"] = "bbot"
        return url, kwargs

    async def setup(self):
        self._request_lock = asyncio.Lock()
        self._last_request_time = 0
        return True

    async def filter_event(self, event):
        # forward lookups only for in-scope names; the extra hop is for IPs
        if event.type == "DNS_NAME" and event.scope_distance > self.scan.scope_search_distance:
            return False, "DNS_NAME is out of scope"
        if event.type == "IP_ADDRESS" and self.is_shared_infrastructure(event):
            return False, "IP belongs to a CDN / cloud provider (shared hosting)"
        return True

    async def handle_event(self, event):
        if event.type == "DNS_NAME":
            await self.handle_forward(event)
        else:
            await self.handle_reverse(event)

    async def handle_forward(self, event):
        self.remember_org_name(event.data)
        for record in await self.query(f"pdns/forward/{self.helpers.quote(event.data)}"):
            rrtype, rrdata = record.get("rrtype", ""), str(record.get("rrdata", "")).rstrip(".")
            if rrtype in ("A", "AAAA"):
                event_type = "IP_ADDRESS"
            elif rrtype in ("NS", "MX", "CNAME"):
                event_type = "DNS_NAME"
            else:
                continue
            if rrdata and rrdata != event.data:
                await self.emit_record(rrdata, event_type, event, record, f"{rrtype} record of {event.data}")

    async def handle_reverse(self, event):
        records = [r for r in await self.query(f"pdns/reverse/{event.data}") if r.get("rrname")]
        names = {str(r["rrname"]).rstrip(".").lower() for r in records}
        if not await self.reverse_names_allowed(event.data, len(names), lambda: self.network_owner(event.data)):
            return
        for record in records:
            name = str(record["rrname"]).rstrip(".").lower()
            await self.emit_record(name, "DNS_NAME", event, record, f"name that pointed to {event.data}")

    async def emit_record(self, data, event_type, parent, record, relation):
        first, last = record.get("time_first"), record.get("time_last")
        tags = []
        if isinstance(last, (int, float)) and time.time() - last > self.config.get("historical_days", 90) * 86400:
            tags.append("pdns-historical")
        await self.emit_event(
            data,
            event_type,
            parent=parent,
            tags=tags,
            last_seen=last,
            context=f"{{module}} found {{event.type}}: {{event.pretty_string}} in Robtex passive DNS ({relation}, seen {self._date(first)} .. {self._date(last)})",
        )

    async def network_owner(self, ip):
        """Owner descriptions of the IP's route and AS, from Robtex ipquery."""
        records = await self.query(f"ipquery/{ip}")
        info = records[0] if records else {}
        return [info.get("routedesc"), info.get("asname"), info.get("asdesc")]

    @staticmethod
    def _date(timestamp):
        if not isinstance(timestamp, (int, float)):
            return "?"
        return time.strftime("%Y-%m-%d", time.gmtime(timestamp))

    async def query(self, path):
        """Returns the list of pDNS records (the API answers with newline-delimited JSON)."""
        async with self._request_lock:
            interval = 60 / max(1, self.config.get("requests_per_minute", 30))
            wait = self._last_request_time + interval - time.time()
            if wait > 0:
                await self.helpers.sleep(wait)
            self._last_request_time = time.time()
        r = await self.api_request(f"{self.base_url}/{path}")
        if getattr(r, "status_code", 0) != 200:
            return []
        records = []
        for line in r.text.splitlines():
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict):
                records.append(record)
        return records
