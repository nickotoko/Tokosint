from .base import ModuleTestBase


class TestIP2Location(ModuleTestBase):
    targets = ["8.8.8.8"]
    config_overrides = {"modules": {"ip2location": {"api_key": "asdf"}}}
    lookup_url = "http://api.ip2location.io/?key=asdf&ip=8.8.8.8&format=json&source=bbot"

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url=self.lookup_url,
            json={
                "ip": "8.8.8.8",
                "country_code": "US",
                "country_name": "United States of America",
                "region_name": "California",
                "city_name": "Mountain View",
                "latitude": 37.405992,
                "longitude": -122.078515,
                "zip_code": "94043",
                "time_zone": "-07:00",
                "asn": "15169",
                "as": "Google LLC",
                "is_proxy": False,
                "message": "Limit to 1,000 queries per day.",
            },
        )

    def check(self, module_test, events):
        assert any(
            e.type == "GEOLOCATION" and e.data["ip"] == "8.8.8.8" and e.data["city_name"] == "Mountain View"
            for e in events
        ), "Failed to geolocate IP"


class TestIP2Location_Keyless(TestIP2Location):
    module_name = "ip2location"
    config_overrides = {}
    lookup_url = "http://api.ip2location.io/?ip=8.8.8.8&format=json&source=bbot"

    def check(self, module_test, events):
        super().check(module_test, events)
        geo = [e for e in events if e.type == "GEOLOCATION"]
        assert all("message" not in e.data for e in geo), "service notice must not end up in the event"


class TestIP2Location_NoResponse(TestIP2Location):
    """The API did not answer (network error, quota): no GEOLOCATION and no crash
    (previously: UnboundLocalError 'geo_data' in handle_event)."""

    module_name = "ip2location"

    async def setup_after_prep(self, module_test):
        module = module_test.module
        self.errors = []

        async def no_response(*args, **kwargs):
            return None

        module.api_request = no_response
        original = module.handle_event

        async def guarded(event):
            try:
                return await original(event)
            except Exception as e:  # noqa: BLE001 - recorded for the assertion
                self.errors.append(e)
                raise

        module.handle_event = guarded

    def check(self, module_test, events):
        assert not self.errors, self.errors
        assert not any(e.type == "GEOLOCATION" for e in events)
