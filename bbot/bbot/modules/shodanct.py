import time

from bbot.modules.templates.subdomain_enum import subdomain_enum
from bbot.core.config.models import BaseModuleConfig, Field


class shodanct(subdomain_enum):
    """
    Query Shodan's certificate transparency monitor (ctl.shodan.io) for certificates of a domain.

    Subdomains are emitted from the certificates' SANs. Other domains sharing a certificate with the
    target (e.g. a company's other brands) are emitted as affiliates, unless the certificate carries
    so many names that it's probably a shared (CDN / hosting) certificate. No key required.
    """

    flags = ["safe", "subdomain-enum", "affiliates", "passive"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {
        "freshness": "historical",
        "description": "Query Shodan's certificate transparency monitor for subdomains and co-hosted domains",
        "created_date": "2026-11-01",
        "author": "@nickotoko",
    }

    class Config(BaseModuleConfig):
        max_shared_sans: int = Field(
            10, description="Ignore other domains from certificates with more SANs than this (shared certificates)"
        )

    base_url = "https://ctl.shodan.io/api/v1/domain"

    async def handle_event(self, event):
        query = self.make_query(event)
        r = await self.api_request(f"{self.base_url}/{self.helpers.quote(query)}")
        try:
            certs = r.json()
        except Exception:
            return
        if not isinstance(certs, list):
            return

        subdomains, affiliates = {}, {}
        max_shared_sans = self.config.get("max_shared_sans", 10)
        for cert in certs:
            if not isinstance(cert, dict):
                continue
            names = {str(n).lower().lstrip("*.").rstrip(".") for n in cert.get("san_dns_names") or [] if n}
            for name in names:
                if name == query or name.endswith(f".{query}"):
                    subdomains.setdefault(name, cert)
                elif len(names) <= max_shared_sans:
                    affiliates.setdefault(name, cert)

        for name, cert in subdomains.items():
            if name != event.data:
                await self.emit_event(
                    name, "DNS_NAME", parent=event, abort_if=self.abort_if, context=self.context(query, cert)
                )
        for name, cert in affiliates.items():
            await self.emit_event(
                name,
                "DNS_NAME",
                parent=event,
                tags=["affiliate"],
                context=f"{self.context(query, cert)} (shares a certificate with {query})",
            )

    @staticmethod
    def context(query, cert):
        def date(ts):
            return time.strftime("%Y-%m-%d", time.gmtime(ts)) if isinstance(ts, (int, float)) else "?"

        return (
            f'{{module}} searched Shodan CT for "{query}" and found {{event.type}}: {{event.pretty_string}} '
            f"in certificate {cert.get('subject_cn', '?')} by {cert.get('issuer_cn', '?')} "
            f"({date(cert.get('not_before'))} .. {date(cert.get('not_after'))})"
        )
