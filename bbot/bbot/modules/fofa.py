import base64
import ipaddress
from urllib.parse import urlparse

from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field
from typing import Optional


class fofa(BaseModule):
    """
    Query the FOFA search engine for hosts, open ports and technologies.

    API reference: https://en.fofa.info/api
    """

    watched_events = ["IP_ADDRESS", "DNS_NAME"]
    produced_events = ["DNS_NAME", "OPEN_TCP_PORT", "TECHNOLOGY"]
    flags = ["safe", "passive", "subdomain-enum"]
    meta = {
        "freshness": "historical",
        "description": "Query FOFA API for hosts, open ports and technologies",
        "created_date": "2025-08-27",
        "author": "@nickotoko",
    }

    class Config(BaseModuleConfig):
        api_key: str | list[str] = Field("", description="FOFA API key", sensitive=True, mandatory=True)
        size: int = Field(100, description="Max results per search query")
        host_details: bool = Field(True, description="Query /host/<ip> for per-port products of every found IP")
        retries: Optional[int] = Field(
            None, description="How many times to retry API requests. Overrides the global web.api_retries setting."
        )

    base_url = "https://fofa.info/api/v1"

    async def setup(self):
        self.ips_detailed = set()
        return await self.require_api_key()

    @property
    def api_retries(self):
        return self.config.get("retries", None) or super().api_retries

    def prepare_api_request(self, url, kwargs):
        # append rather than rebuild the query, so already-encoded params aren't encoded twice
        separator = "&" if "?" in url else "?"
        return f"{url}{separator}key={self.helpers.quote(self.api_key)}", kwargs

    async def ping(self):
        # FOFA answers 200 with {"error": true} on a bad key
        r = await self.api_request(f"{self.base_url}/info/my")
        j = self._json(r)
        if j is None:
            raise ValueError(getattr(r, "text", "no response from server"))

    def _incoming_dedup_hash(self, event):
        return hash(event.data)

    async def handle_event(self, event):
        query = self.make_query(event)
        qbase64 = base64.b64encode(query.encode()).decode()
        params = {"qbase64": qbase64, "fields": "host,ip,port", "size": self.config.get("size", 100)}
        url = self.helpers.add_get_params(f"{self.base_url}/search/all", params).geturl()
        j = self._json(await self.api_request(url))
        if j is None:
            return

        ips = set()
        for result in j.get("results", []):
            try:
                host_or_url, ip, port = result
            except (TypeError, ValueError):
                self.debug(f"Unexpected FOFA result format: {result}")
                continue
            hostname = self._extract_hostname(host_or_url)
            if hostname and hostname != event.data:
                await self.emit_event(
                    hostname,
                    "DNS_NAME",
                    parent=event,
                    context=f'{{module}} searched FOFA for "{query}" and found {{event.type}}: {{event.data}}',
                )
            await self.emit_event(
                self.helpers.make_netloc(hostname or ip, port),
                "OPEN_TCP_PORT",
                parent=event,
                context=f'{{module}} searched FOFA for "{query}" and found {{event.type}}: {{event.data}}',
            )
            if ip:
                ips.add(ip)

        if self.config.get("host_details", True):
            for ip in ips:
                await self.handle_host_details(event, ip)

    def make_query(self, event):
        if event.type == "IP_ADDRESS":
            return f'ip="{event.data}"'
        return f'domain="{event.data}" || cert.subject.cn*="*{event.data}" || cert.issuer.cn*="*{event.data}"'

    async def handle_host_details(self, event, ip):
        if ip in self.ips_detailed:
            return
        self.ips_detailed.add(ip)
        url = self.helpers.add_get_params(f"{self.base_url}/host/{ip}", {"detail": "true"}).geturl()
        j = self._json(await self.api_request(url))
        if j is None:
            return
        for port_info in j.get("ports", []) or []:
            port = port_info.get("port")
            if not port:
                continue
            netloc = self.helpers.make_netloc(ip, port)
            context = f"{{module}} queried FOFA host details for {ip} and found {{event.type}}: {{event.data}}"
            await self.emit_event(netloc, "OPEN_TCP_PORT", parent=event, context=context)
            for product in port_info.get("products", []) or []:
                technology = product.get("product", "")
                if technology:
                    await self.emit_event(
                        {"technology": technology, "host": ip, "url": f"http://{netloc}"},
                        "TECHNOLOGY",
                        parent=event,
                        context=context,
                    )

    def _json(self, r):
        """Returns the decoded body of a successful FOFA response, otherwise None."""
        if r is None:
            return None
        try:
            j = r.json()
        except Exception as e:
            self.verbose(f"Error parsing FOFA response: {e}")
            return None
        if not isinstance(j, dict) or j.get("error"):
            self.verbose(f"FOFA API returned error: {j.get('errmsg', j) if isinstance(j, dict) else j}")
            return None
        return j

    @staticmethod
    def _extract_hostname(host_or_url):
        parsed = urlparse(host_or_url if "://" in host_or_url else f"//{host_or_url}")
        hostname = parsed.hostname
        if not hostname:
            return None
        try:
            ipaddress.ip_address(hostname)
            return None
        except ValueError:
            return hostname
