from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey
from bbot.core.config.models import BaseModuleConfig, Field


class hunterio(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["EMAIL_ADDRESS", "DNS_NAME", "URL_UNVERIFIED"]
    flags = ["safe", "passive", "email-enum", "subdomain-enum"]
    meta = {
        "freshness": "historical",
        "description": "Query hunter.io for emails",
        "created_date": "2022-04-25",
        "author": "@TheTechromancer",
    }

    class Config(BaseModuleConfig):
        api_key: str | list[str] = Field("", description="Hunter.IO API key", sensitive=True, mandatory=True)
        page_size: int = Field(
            10,
            description="Emails per request. The Free plan allows at most 10 (and no further pages), paid plans 100",
        )

    base_url = "https://api.hunter.io/v2"
    ping_url = f"{base_url}/account?api_key={{api_key}}"

    async def setup(self):
        self.limit = self.config.get("page_size", 10)
        return await super().setup()

    def _api_response_is_success(self, r):
        # the plan's result cap is a final answer, not a transient error worth retrying with another key
        return super()._api_response_is_success(r) or self._is_plan_limit(r)

    @staticmethod
    def _is_plan_limit(r):
        if getattr(r, "status_code", 0) != 400:
            return False
        try:
            return any(e.get("id") == "pagination_error" for e in r.json().get("errors", []))
        except Exception:
            return False

    async def handle_event(self, event):
        query = self.make_query(event)
        for entry in await self.query(query):
            email = entry.get("value", "")
            sources = entry.get("sources", [])
            if email:
                email_event = self.make_event(email, "EMAIL_ADDRESS", event)
                if email_event:
                    await self.emit_event(
                        email_event,
                        context=f'{{module}} queried Hunter.IO API for "{query}" and found {{event.type}}: {{event.pretty_string}}',
                    )
                    for source in sources:
                        domain = source.get("domain", "")
                        if domain:
                            await self.emit_event(
                                domain,
                                "DNS_NAME",
                                email_event,
                                context=f"{{module}} originally found {email} at {{event.type}}: {{event.pretty_string}}",
                            )
                        url = source.get("uri", "")
                        if url:
                            await self.emit_event(
                                url,
                                "URL_UNVERIFIED",
                                email_event,
                                context=f"{{module}} originally found {email} at {{event.type}}: {{event.pretty_string}}",
                            )

    async def query(self, query):
        emails = []
        url = (
            f"{self.base_url}/domain-search?domain={query}&api_key={{api_key}}" + "&limit={page_size}&offset={offset}"
        )
        agen = self.api_page_iter(url, page_size=self.limit)
        try:
            async for j in agen:
                errors = j.get("errors", [])
                if errors:
                    self.verbose(f'Stopping pagination for "{query}": {errors[0].get("details", errors)}')
                    break
                new_emails = j.get("data", {}).get("emails", [])
                if not new_emails:
                    break
                emails += new_emails
                if len(emails) >= j.get("meta", {}).get("results", 0):
                    break
        finally:
            await agen.aclose()
        return emails
