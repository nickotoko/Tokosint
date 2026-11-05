from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field


class IP2Location(BaseModule):
    """
    IP2Location.io Geolocation API.
    """

    watched_events = ["IP_ADDRESS"]
    produced_events = ["GEOLOCATION"]
    flags = ["safe", "passive"]
    meta = {
        "freshness": "current",
        "description": "Query IP2location.io's API for geolocation information. ",
        "created_date": "2023-09-12",
        "author": "@TheTechromancer",
    }

    class Config(BaseModuleConfig):
        api_key: str | list[str] = Field(
            "",
            description="IP2location.io API Key (optional: keyless access is limited to 1,000 queries/day, a free key gives 50K/month)",
            sensitive=True,
        )
        lang: str = Field(
            "",
            description="Translation information(ISO639-1). The translation is only applicable for continent, country, region and city name.",
        )

    scope_distance_modifier = 1
    _priority = 2
    suppress_dupes = False

    base_url = "http://api.ip2location.io"

    async def setup(self):
        self.lang = self.config.get("lang", "")
        if self.config.get("api_key", ""):
            return await self.require_api_key()
        self.verbose("No API key set, using keyless access (1,000 queries/day)")
        return True

    async def ping(self):
        url = self.build_url("8.8.8.8")
        await super().ping(url)

    def build_url(self, data):
        key = "key={api_key}&" if self.api_key else ""
        url = f"{self.base_url}/?{key}ip={data}&format=json&source=bbot"
        if self.lang:
            url = f"{url}&lang={self.lang}"
        return url

    async def handle_event(self, event):
        try:
            url = self.build_url(event.data)
            result = await self.api_request(url)
            if not result:
                self.verbose(f"No response from {url}")
                return
            geo_data = result.json()
            if not isinstance(geo_data, dict) or not geo_data:
                self.verbose(f"No JSON response from {url}")
                return
        except Exception:
            self.verbose(f"Error retrieving results for {event.pretty_string}", trace=True)
            return

        # "message" is a service notice (e.g. the keyless quota), not geolocation data
        geo_data = {k: v for k, v in geo_data.items() if v is not None and k != "message"}
        if "error" in geo_data:
            error_msg = geo_data.get("error").get("error_message", "")
            if error_msg:
                self.warning(error_msg)
        elif geo_data:
            country = geo_data.get("country_name", "unknown country")
            region = geo_data.get("region_name", "unknown region")
            city = geo_data.get("city_name", "unknown city")
            lat = geo_data.get("latitude", "")
            long = geo_data.get("longitude", "")
            description = f"{city}, {region}, {country} ({lat}, {long})"
            await self.emit_event(
                geo_data,
                "GEOLOCATION",
                event,
                context=f'{{module}} queried IP2Location API for "{event.pretty_string}" and found {{event.type}}: {description}',
            )
