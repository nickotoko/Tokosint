import base64
import ipaddress
from urllib.parse import urlparse

from bbot.modules.base import BaseModule
from bbot.modules.templates.shared_hosting import SharedHostingConfig, shared_hosting_filter
from bbot.core.config.models import Field
from typing import Optional


class fofa(shared_hosting_filter, BaseModule):
    """
    Query the FOFA search engine for hosts, open ports and technologies.

    - DNS_NAME -> search `domain="d" || cert.subject.cn="d" || cert.subject.cn*="*.d"`. FOFA's `*=` is a substring
      match, so the pattern needs the dot: `*d` would also match `foo-d`, `food` etc. Results are checked again
      on our side: a hostname must be d or a subdomain of d; a result on another host/IP is kept only when its
      certificate is issued for d (and then reported as ip:port, the foreign name is not emitted).
    - IP_ADDRESS -> per-port products of the IP (/host/<ip>). The IP is the parent of what is found there, and
      IPs of someone else's infrastructure (CDN, anti-DDoS front, cloud, third-party providers of the target) are
      skipped: their ports belong to the provider, not to the target.

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

    class Config(SharedHostingConfig):
        api_key: str | list[str] = Field("", description="FOFA API key", sensitive=True, mandatory=True)
        size: int = Field(100, description="Results per page of a search query")
        max_pages: int = Field(
            5, description="Max pages per search query (each page is a separate API query and spends its quota)"
        )
        host_details: bool = Field(
            True, description="Query /host/<ip> for per-port products of IPs (not of CDN / proxy / third-party IPs)"
        )
        retries: Optional[int] = Field(
            None, description="How many times to retry API requests. Overrides the global web.api_retries setting."
        )

    # IPs of in-scope hosts sit one hop out; host details need to see them
    scope_distance_modifier = 1

    base_url = "https://fofa.info/api/v1"
    # lastupdatetime: when FOFA last saw the service (the finding's last_seen). Only paid tiers may request it:
    # others get {"error": true, "errmsg": "[820001] ..."} for the whole query, then we search without it
    search_fields = "host,ip,port,cert.subject.cn,lastupdatetime"
    base_search_fields = "host,ip,port,cert.subject.cn"
    no_field_permission = "820001"
    # validity: the IP belongs to a provider the target uses (its MX / NS / SaaS), not to the target
    foreign_ip_tags = ("third-party",)

    async def setup(self):
        self._search_fields = self.search_fields
        return await self.require_api_key()

    def _api_response_is_success(self, r):
        # FOFA reports errors (bad key, no permission, no F-points) with HTTP 200 and {"error": true}:
        # count them as failed requests, not as answers without data
        if not super()._api_response_is_success(r):
            return False
        try:
            j = r.json()
        except Exception:
            return True
        if not (isinstance(j, dict) and j.get("error")):
            return True
        # no permission for lastupdatetime: not worth retrying, search() repeats the query without the field
        return self.no_field_permission in str(j.get("errmsg", "")) and self._search_fields != self.base_search_fields

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

    async def filter_event(self, event):
        if event.type == "DNS_NAME":
            # domain searches only for in-scope names; the extra hop is for IPs
            if event.scope_distance > self.scan.scope_search_distance:
                return False, "DNS_NAME is out of scope"
            return True
        if not self.config.get("host_details", True):
            return False, "host_details is disabled"
        if self.is_shared_infrastructure(event):
            return False, "IP belongs to a CDN / proxy / cloud provider (shared hosting)"
        if any(t in self.foreign_ip_tags for t in event.tags):
            return False, "IP is third-party infrastructure"
        return True

    async def handle_event(self, event):
        if event.type == "DNS_NAME":
            await self.handle_domain(event)
        else:
            await self.handle_host_details(event)

    def make_query(self, event):
        return f'domain="{event.data}" || cert.subject.cn="{event.data}" || cert.subject.cn*="*.{event.data}"'

    async def handle_domain(self, event):
        domain = event.data
        query = self.make_query(event)
        context = f'{{module}} searched FOFA for "{query}" and found {{event.type}}: {{event.data}}'
        async for result in self.search(query):
            if not isinstance(result, (list, tuple)) or len(result) < 3:
                self.debug(f"Unexpected FOFA result format: {result}")
                continue
            host_or_url, ip, port = result[:3]
            cert_cn = result[3] if len(result) > 3 else ""
            seen = result[4] if len(result) > 4 else None
            if not port:
                continue
            hostname = self._extract_hostname(str(host_or_url or ""))
            if hostname and self.name_matches(hostname, domain):
                if hostname != domain:
                    await self.emit_event(hostname, "DNS_NAME", parent=event, context=context, last_seen=seen)
                await self.emit_event(self.helpers.make_netloc(hostname, port), "OPEN_TCP_PORT", parent=event,
                                      context=context, last_seen=seen)  # fmt: skip
            elif ip and (self.cert_matches(cert_cn, domain) or self.scan.in_target(ip)):
                # a server (or a foreign name) presenting the target's certificate, or an address of the target
                # itself: report the address only
                await self.emit_event(
                    self.helpers.make_netloc(ip, port),
                    "OPEN_TCP_PORT",
                    parent=event,
                    last_seen=seen,
                    context=f'{{module}} searched FOFA for "{query}" and found {{event.type}}: {{event.data}}'
                    + (f" serving a certificate for {cert_cn}" if cert_cn else ""),
                )
            else:
                self.debug(f"Skipping FOFA result unrelated to {domain}: {host_or_url} ({ip}:{port}, cn={cert_cn!r})")

    async def search(self, query):
        """Yields the results of a search query, page by page (up to max_pages)."""
        qbase64 = base64.b64encode(query.encode()).decode()
        size = max(1, int(self.config.get("size", 100)))
        max_pages = max(1, int(self.config.get("max_pages", 5)))
        fetched = total = 0
        page = 1
        while page <= max_pages:
            params = {"qbase64": qbase64, "fields": self._search_fields, "size": size, "page": page}
            url = self.helpers.add_get_params(f"{self.base_url}/search/all", params).geturl()
            r = await self.api_request(url)
            j = self._raw_json(r)
            if isinstance(j, dict) and j.get("error"):
                errmsg = str(j.get("errmsg", ""))
                if self.no_field_permission in errmsg and self._search_fields != self.base_search_fields:
                    self.warning(
                        f"FOFA key may not request lastupdatetime ({errmsg}): searching without it, no last_seen"
                    )
                    self._search_fields = self.base_search_fields
                    continue
                self.warning(f"FOFA search failed for {query!r}: {errmsg or j}")
                return
            if not isinstance(j, dict):
                return
            results = j.get("results") or []
            for result in results:
                yield result
            fetched += len(results)
            total = j.get("size") or 0
            if not results or len(results) < size or fetched >= total:
                return
            page += 1
        if fetched < total:
            self.verbose(f"FOFA search {query!r}: {total:,} results, fetched {fetched:,} (max_pages={max_pages})")

    @staticmethod
    def name_matches(hostname, domain):
        """hostname is the domain or its subdomain (not just a name that ends with the same letters)."""
        hostname, domain = str(hostname or "").lower().rstrip("."), str(domain).lower().rstrip(".")
        return hostname == domain or hostname.endswith(f".{domain}")

    @classmethod
    def cert_matches(cls, cert_cn, domain):
        """The certificate CN covers the domain or its subdomain (`*.d`, `d`, `x.d`, `*.x.d`)."""
        cn = str(cert_cn or "").strip().lower()
        if cn.startswith("*."):
            cn = cn[2:]
        return bool(cn) and cls.name_matches(cn, domain)

    async def handle_host_details(self, event):
        ip = str(event.data)
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
            seen = port_info.get("update_time") or j.get("update_time")
            await self.emit_event(netloc, "OPEN_TCP_PORT", parent=event, context=context, last_seen=seen)
            for product in port_info.get("products", []) or []:
                technology = product.get("product", "")
                if technology:
                    await self.emit_event(
                        {"technology": technology, "host": ip, "port": port, "url": f"http://{netloc}"},
                        "TECHNOLOGY",
                        parent=event,
                        context=context,
                        last_seen=seen,
                    )

    def _raw_json(self, r):
        if r is None:
            return None
        try:
            return r.json()
        except Exception as e:
            self.verbose(f"Error parsing FOFA response: {e}")
            return None

    def _json(self, r):
        """Returns the decoded body of a successful FOFA response, otherwise None."""
        j = self._raw_json(r)
        if j is None:
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
