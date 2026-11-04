from bbot.modules.templates.subdomain_enum import subdomain_enum


class hudsonrock(subdomain_enum):
    """
    Query Hudson Rock's free Cavalier OSINT API for infostealer data about a domain:
    login pages whose credentials were stolen from infected machines, and compromise statistics.

    No key required. https://www.hudsonrock.com/free-tools
    """

    flags = ["safe", "subdomain-enum", "passive"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME", "URL_UNVERIFIED", "FINDING"]
    meta = {
        "freshness": "historical",
        "description": "Query Hudson Rock for infostealer-compromised login pages and statistics of a domain",
        "created_date": "2026-11-01",
        "author": "@nickotoko",
    }

    base_url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"

    async def handle_event(self, event):
        query = self.make_query(event)
        url = self.helpers.add_get_params(f"{self.base_url}/search-by-domain", {"domain": query}).geturl()
        try:
            j = (await self.api_request(url)).json()
        except Exception as e:
            self.verbose(f'Error querying Hudson Rock for "{query}": {e}')
            return
        if not isinstance(j, dict) or not j.get("total"):
            return

        context = f'{{module}} searched Hudson Rock infostealer data for "{query}" and found {{event.type}}: {{event.pretty_string}}'
        hostnames, urls = set(), set()
        for item in (j.get("data") or {}).get("all_urls") or []:
            login_url = item.get("url", "")
            # urls of non-public parts are masked by the free API
            if not login_url or "•" in login_url:
                continue
            urls.add(login_url)
            parsed = self.helpers.urlparse(login_url)
            if parsed.hostname:
                hostnames.add(parsed.hostname.lower())

        for hostname in hostnames - {event.data}:
            await self.emit_event(hostname, "DNS_NAME", parent=event, abort_if=self.abort_if, context=context)
        for login_url in urls:
            if self.scan.in_scope(self.helpers.urlparse(login_url).hostname or ""):
                await self.emit_event(login_url, "URL_UNVERIFIED", parent=event, tags=["login-page"], context=context)

        families = {k: v for k, v in (j.get("stealerFamilies") or {}).items() if k != "total" and v}
        description = (
            f"Infostealer compromises for {query}: {j.get('employees', 0):,} employees "
            f"(last {(j.get('last_employee_compromised') or 'n/a')[:10]}), {j.get('users', 0):,} users "
            f"(last {(j.get('last_user_compromised') or 'n/a')[:10]}), {j.get('third_parties', 0):,} third parties"
        )
        if families:
            description += ". Stealer families: " + ", ".join(f"{k} ({v})" for k, v in families.items())
        await self.emit_event(
            {
                "host": str(event.host),
                "name": "Hudson Rock - Infostealer Compromises",
                "description": description,
                "severity": "MEDIUM" if j.get("employees") else "LOW",
                "confidence": "MEDIUM",
            },
            "FINDING",
            parent=event,
            context=f'{{module}} searched Hudson Rock infostealer data for "{query}" and found {{event.type}}',
        )
