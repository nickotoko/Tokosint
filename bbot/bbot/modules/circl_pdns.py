import json
import time

from bbot.modules.base import BaseModule
from bbot.modules.templates.shared_hosting import SharedHostingConfig, shared_hosting_filter
from bbot.core.config.models import Field


class circl_pdns(shared_hosting_filter, BaseModule):
    """
    Query CIRCL Passive DNS (https://www.circl.lu/services/passive-dns/).

    - DNS_NAME -> forward pDNS: IPs, name servers, mail servers and CNAMEs the name has pointed to
    - IP_ADDRESS -> reverse pDNS: names that have pointed to the IP (skipped for shared hosting / proxy fronts)

    Access is granted by CIRCL on request: HTTP basic auth with the account e-mail as the user and the API token
    as the password (as in PyPDNS). The answer is newline-delimited JSON in the
    Passive DNS Common Output Format (rrname, rrtype, rdata, time_first, time_last, count), paginated with
    the dribble-paginate-* headers. Active resolution on CIRCL's side is disabled: only recorded data is returned.
    Records not seen for `historical_days` are tagged pdns-historical.
    """

    watched_events = ["DNS_NAME", "IP_ADDRESS"]
    produced_events = ["DNS_NAME", "IP_ADDRESS"]
    flags = ["safe", "passive", "subdomain-enum", "affiliates"]
    meta = {
        "freshness": "historical",
        "description": "Query CIRCL passive DNS for historical records of names and IPs",
        "created_date": "2026-11-06",
        "author": "@nickotoko",
        "auth_required": True,
    }

    class Config(SharedHostingConfig):
        username: str = Field(
            "", description="CIRCL account e-mail (the Basic auth user)", sensitive=True, mandatory=True
        )
        password: str = Field(
            "", description="CIRCL API token (the Basic auth password)", sensitive=True, mandatory=True
        )
        historical_days: int = Field(90, description="Records not seen for this many days are tagged pdns-historical")
        page_size: int = Field(100, description="Records per page (the server may cap it)")
        max_pages: int = Field(5, description="Max pages per query")

    # IPs of in-scope hosts sit one hop out; reverse lookups need to see them
    scope_distance_modifier = 1

    base_url = "https://www.circl.lu/pdns/query"
    forward_types = {"A": "IP_ADDRESS", "AAAA": "IP_ADDRESS", "CNAME": "DNS_NAME", "NS": "DNS_NAME", "MX": "DNS_NAME"}

    async def setup(self):
        username = str(self.config.get("username", "") or "").strip()
        password = str(self.config.get("password", "") or "").strip()
        if not username or not password:
            return None, "No CIRCL Passive DNS credentials (e-mail and API token)"
        if "@" not in username and "@" in password:
            # the e-mail went into the token field and vice versa (CIRCL answers 401 to the swapped pair)
            self.warning("CIRCL credentials look swapped (the e-mail is in the password field): using e-mail:token")
            username, password = password, username
        self._auth = (username, password)
        return True

    def prepare_api_request(self, url, kwargs):
        kwargs["auth"] = self._auth
        kwargs["headers"]["dribble-disable-active-query"] = "1"
        return url, kwargs

    async def filter_event(self, event):
        # forward lookups only for in-scope names; the extra hop is for IPs
        if event.type == "DNS_NAME" and event.scope_distance > self.scan.scope_search_distance:
            return False, "DNS_NAME is out of scope"
        if event.type == "IP_ADDRESS" and self.is_shared_infrastructure(event):
            return False, "IP belongs to a CDN / proxy / cloud provider (shared hosting)"
        return True

    async def handle_event(self, event):
        if event.type == "DNS_NAME":
            await self.handle_forward(event)
        else:
            await self.handle_reverse(event)

    async def handle_forward(self, event):
        self.remember_org_name(event.data)
        for record in await self.query(event.data):
            if self._norm(record.get("rrname")) != event.data:
                continue
            rrtype = str(record.get("rrtype", "")).upper()
            event_type = self.forward_types.get(rrtype)
            if event_type is None:
                continue
            for value in self._rdata(record):
                if rrtype == "MX":
                    # "10 mx.example.com" -> "mx.example.com"
                    value = value.split()[-1] if value.split() else ""
                value = self._norm(value)
                if value and value != event.data:
                    await self.emit_record(value, event_type, event, record, f"{rrtype} record of {event.data}")

    async def handle_reverse(self, event):
        ip = str(event.data)
        records = [
            r for r in await self.query(ip) if r.get("rrname") and ip in self._rdata(r)
        ]  # fmt: skip
        names = {self._norm(r["rrname"]) for r in records}
        names.discard("")
        if not await self.reverse_names_allowed(ip, len(names), self._no_owner):
            return
        for record in records:
            name = self._norm(record["rrname"])
            if name:
                await self.emit_record(name, "DNS_NAME", event, record, f"name that pointed to {ip}")

    async def _no_owner(self):
        # CIRCL has no network-owner lookup; the own-network allowance then relies on cloud/proxy tags only
        return []

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
            context=f"{{module}} found {{event.type}}: {{event.pretty_string}} in CIRCL passive DNS ({relation}, seen {self._date(first)} .. {self._date(last)})",
        )

    @staticmethod
    def _norm(value):
        return str(value or "").strip().rstrip(".").lower()

    @staticmethod
    def _rdata(record):
        rdata = record.get("rdata")
        values = rdata if isinstance(rdata, list) else [rdata]
        return [str(v).strip() for v in values if v not in (None, "")]

    @staticmethod
    def _date(timestamp):
        if not isinstance(timestamp, (int, float)):
            return "?"
        return time.strftime("%Y-%m-%d", time.gmtime(timestamp))

    async def query(self, q):
        """All pDNS records for a name or an IP, following the dribble pagination cursor."""
        records, cursor = [], None
        url = f"{self.base_url}/{self.helpers.quote(q)}"
        for _ in range(max(1, self.config.get("max_pages", 5))):
            headers = {"dribble-paginate-count": str(self.config.get("page_size", 100))}
            if cursor is not None:
                headers["dribble-paginate-cursor"] = cursor
            r = await self.api_request(url, headers=headers)
            status = getattr(r, "status_code", 0)
            if status != 200:
                if status in (401, 403):
                    self.warning(f"CIRCL Passive DNS refused the credentials (HTTP {status})")
                break
            for line in r.text.splitlines():
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if isinstance(record, dict):
                    records.append(record)
            cursor = r.headers.get("x-dribble-cursor")
            if not cursor:
                break
        return records
