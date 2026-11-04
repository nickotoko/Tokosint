from bbot.modules.templates.censys import censys
from bbot.core.config.models import BaseModuleConfig, Field


class censys_ip(censys):
    """
    Query the Censys Platform host lookup (/v3/global/asset/host/{ip}) for open ports,
    protocols, technologies, TLS certificate names and DNS names of an IP.
    """

    watched_events = ["IP_ADDRESS"]
    produced_events = [
        "DNS_NAME",
        "URL_UNVERIFIED",
        "OPEN_TCP_PORT",
        "OPEN_UDP_PORT",
        "TECHNOLOGY",
        "PROTOCOL",
    ]
    flags = ["safe", "passive"]
    meta = {
        "freshness": "current",
        "description": "Query the Censys Platform API for hosts by IP address",
        "created_date": "2026-01-26",
        "author": "@TheTechromancer",
    }

    class Config(BaseModuleConfig):
        api_key: str | list[str] = Field(
            "", description="Censys Platform Personal Access Token", sensitive=True, mandatory=True
        )
        dns_names_limit: int = Field(
            100, description="Maximum number of DNS names to extract from dns.names (default 100)"
        )
        in_scope_only: bool = Field(
            True, description="Only query in-scope IPs. If False, will query up to distance 1."
        )

    scope_distance_modifier = 1
    host_accept = "application/vnd.censys.api.v3.host.v1+json"

    async def setup(self):
        self.dns_names_limit = self.config.get("dns_names_limit", 100)
        if not self.config.get("in_scope_only", True):
            self.warning(
                "in_scope_only is disabled. This module queries each IP individually and may consume a lot of API credits!"
            )
        return await super().setup()

    async def filter_event(self, event):
        in_scope_only = self.config.get("in_scope_only", True)
        max_scope_distance = 0 if in_scope_only else (self.scan.scope_search_distance + 1)
        if event.scope_distance > max_scope_distance:
            return False, "event is not in scope"
        return True

    async def handle_event(self, event):
        ip = str(event.host)
        url = f"{self.base_url}/asset/host/{ip}"

        resp = await self.api_request(url, headers={"Accept": self.host_accept})
        if resp is None:
            self.debug(f"No response for {ip}")
            return
        if not self.check_auth(resp):
            return
        if resp.status_code == 404:
            self.debug(f"No data found for {ip}")
            return
        if resp.status_code != 200:
            self.verbose(f"Non-200 status code ({resp.status_code}) for {ip}")
            return

        try:
            host = resp.json().get("result", {}).get("resource", {})
        except Exception as e:
            self.warning(f"Failed to parse JSON response for {ip}: {e}")
            return
        if not host:
            return

        # Track what we've already emitted to avoid duplicates
        seen = set()

        for service in host.get("services", []):
            port = service.get("port")
            transport = (service.get("transport_protocol") or "tcp").upper()
            scanned = (service.get("scan_time") or "")[:10]
            scanned_str = f" (scanned {scanned})" if scanned else ""

            # QUIC uses UDP as transport, so treat it as UDP
            if port and (port, transport) not in seen:
                seen.add((port, transport))
                event_type = "OPEN_UDP_PORT" if transport in ("UDP", "QUIC") else "OPEN_TCP_PORT"
                await self.emit_event(
                    self.helpers.make_netloc(ip, port),
                    event_type,
                    parent=event,
                    context=f"{{module}} found open port on {{event.parent.data}}{scanned_str}",
                )

            # Emit PROTOCOL for non-HTTP services
            service_name = service.get("protocol") or ""
            if service_name.upper() == "UNKNOWN" and transport not in ("TCP", "UDP"):
                service_name = transport
            if service_name and service_name.upper() not in ("HTTP", "HTTPS", "UNKNOWN"):
                protocol_key = ("protocol", service_name.upper(), port)
                if protocol_key not in seen:
                    seen.add(protocol_key)
                    protocol_data = {"host": ip, "protocol": service_name}
                    if port:
                        protocol_data["port"] = port
                    await self.emit_event(
                        protocol_data,
                        "PROTOCOL",
                        parent=event,
                        context="{module} found {event.type}: {event.data[protocol]} on {event.parent.data}",
                    )

            # Extract URLs from HTTP endpoints
            for endpoint in service.get("endpoints", []) or []:
                uri = (endpoint.get("http") or {}).get("uri")
                if uri and uri not in seen:
                    seen.add(uri)
                    await self.emit_event(
                        uri,
                        "URL_UNVERIFIED",
                        parent=event,
                        context="{module} found {event.pretty_string} in HTTP service of {event.parent.data}",
                    )

            # Extract TLS certificate names
            cert = service.get("cert") or {}
            for name in cert.get("names", []) or []:
                await self._emit_host(name, event, seen, "TLS certificate")
            for cn in ((cert.get("parsed") or {}).get("subject") or {}).get("common_name", []) or []:
                await self._emit_host(cn, event, seen, "TLS certificate subject")

            # Extract software/technologies
            for software in service.get("software", []) or []:
                product = software.get("cpe") or software.get("product", "")
                if product:
                    await self.emit_event(
                        {"technology": product, "host": ip},
                        "TECHNOLOGY",
                        parent=event,
                        context="{module} found {event.type}: {event.data[technology]} on {event.parent.data}",
                    )

        # Extract dns.names (limit to configured max)
        dns_names = (host.get("dns") or {}).get("names", []) or []
        for name in dns_names[: self.dns_names_limit]:
            await self._emit_host(name, event, seen, "DNS records")

    async def _emit_host(self, host, event, seen, source):
        """Emit DNS_NAME for a host value."""
        try:
            validated = self.helpers.validators.validate_host(host)
            if validated and validated not in seen:
                seen.add(validated)
                await self.emit_event(
                    validated,
                    "DNS_NAME",
                    parent=event,
                    context=f"{{module}} found {{event.pretty_string}} in {source} of {{event.parent.data}}",
                )
        except ValueError as e:
            self.debug(f"Error validating host {host} in {source}: {e}")
