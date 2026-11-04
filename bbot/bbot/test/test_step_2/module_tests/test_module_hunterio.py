from .base import ModuleTestBase
from bbot.test.mock_blasthttp import MockResponse


class TestHunterio(ModuleTestBase):
    config_overrides = {"modules": {"hunterio": {"api_key": ["asdf", "1234", "4321", "fdsa"]}}}

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="https://api.hunter.io/v2/account?api_key=asdf",
            json={
                "data": {
                    "first_name": "jon",
                    "last_name": "snow",
                    "email": "jon@blacklanternsecurity.notreal",
                    "plan_name": "Starter",
                    "plan_level": 1,
                    "reset_date": "1917-05-23",
                    "team_id": 1234,
                    "calls": {
                        "_deprecation_notice": "Sums the searches and the verifications, giving an imprecise look of the available requests",
                        "used": 999,
                        "available": 2000,
                    },
                    "requests": {
                        "searches": {"used": 998, "available": 1000},
                        "verifications": {"used": 0, "available": 1000},
                    },
                }
            },
        )
        module_test.blasthttp_mock.add_response(
            url="https://api.hunter.io/v2/domain-search?domain=blacklanternsecurity.com&api_key=fdsa&limit=10&offset=0",
            json={
                "data": {
                    "domain": "blacklanternsecurity.com",
                    "disposable": False,
                    "webmail": False,
                    "accept_all": False,
                    "pattern": "{first}",
                    "organization": "Black Lantern Security",
                    "description": None,
                    "twitter": None,
                    "facebook": None,
                    "linkedin": "https://linkedin.com/company/black-lantern-security",
                    "instagram": None,
                    "youtube": None,
                    "technologies": ["jekyll", "nginx"],
                    "country": "US",
                    "state": "CA",
                    "city": "Night City",
                    "postal_code": "12345",
                    "street": "123 Any St",
                    "emails": [
                        {
                            "value": "asdf@blacklanternsecurity.com",
                            "type": "generic",
                            "confidence": 77,
                            "sources": [
                                {
                                    "domain": "blacklanternsecurity.com",
                                    "uri": "http://blacklanternsecurity.com",
                                    "extracted_on": "2021-06-09",
                                    "last_seen_on": "2023-03-21",
                                    "still_on_page": True,
                                }
                            ],
                            "first_name": None,
                            "last_name": None,
                            "position": None,
                            "seniority": None,
                            "department": "support",
                            "linkedin": None,
                            "twitter": None,
                            "phone_number": None,
                            "verification": {"date": None, "status": None},
                        }
                    ],
                    "linked_domains": [],
                },
                "meta": {
                    "results": 2,
                    "limit": 100,
                    "offset": 0,
                    "params": {
                        "domain": "blacklanternsecurity.com",
                        "company": None,
                        "type": None,
                        "seniority": None,
                        "department": None,
                    },
                },
            },
        )
        module_test.blasthttp_mock.add_response(
            url="https://api.hunter.io/v2/domain-search?domain=blacklanternsecurity.com&api_key=4321&limit=10&offset=10",
            json={
                "data": {
                    "domain": "blacklanternsecurity.com",
                    "disposable": False,
                    "webmail": False,
                    "accept_all": False,
                    "pattern": "{first}",
                    "organization": "Black Lantern Security",
                    "description": None,
                    "twitter": None,
                    "facebook": None,
                    "linkedin": "https://linkedin.com/company/black-lantern-security",
                    "instagram": None,
                    "youtube": None,
                    "technologies": ["jekyll", "nginx"],
                    "country": "US",
                    "state": "CA",
                    "city": "Night City",
                    "postal_code": "12345",
                    "street": "123 Any St",
                    "emails": [
                        {
                            "value": "fdsa@blacklanternsecurity.com",
                            "type": "generic",
                            "confidence": 77,
                            "sources": [
                                {
                                    "domain": "blacklanternsecurity.com",
                                    "uri": "http://blacklanternsecurity.com",
                                    "extracted_on": "2021-06-09",
                                    "last_seen_on": "2023-03-21",
                                    "still_on_page": True,
                                }
                            ],
                            "first_name": None,
                            "last_name": None,
                            "position": None,
                            "seniority": None,
                            "department": "support",
                            "linkedin": None,
                            "twitter": None,
                            "phone_number": None,
                            "verification": {"date": None, "status": None},
                        }
                    ],
                    "linked_domains": [],
                },
                "meta": {
                    "results": 2,
                    "limit": 100,
                    "offset": 0,
                    "params": {
                        "domain": "blacklanternsecurity.com",
                        "company": None,
                        "type": None,
                        "seniority": None,
                        "department": None,
                    },
                },
            },
        )

    def check(self, module_test, events):
        assert any(e.data == "asdf@blacklanternsecurity.com" for e in events), "Failed to detect email #1"
        assert any(e.data == "fdsa@blacklanternsecurity.com" for e in events), "Failed to detect email #2"


class TestHunterio_FreePlanLimit(ModuleTestBase):
    """On the Free plan only the first 10 results are available; the plan-limit error ends pagination without retries."""

    module_name = "hunterio"
    config_overrides = {"modules": {"hunterio": {"api_key": "asdf"}}}
    base = "https://api.hunter.io/v2/domain-search?domain=blacklanternsecurity.com&api_key=asdf&limit=10"

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="https://api.hunter.io/v2/account?api_key=asdf", json={"data": {"plan_name": "Free"}}
        )
        module_test.blasthttp_mock.add_response(
            url=f"{self.base}&offset=0",
            json={
                "data": {"emails": [{"value": "asdf@blacklanternsecurity.com", "sources": []}]},
                "meta": {"results": 797, "limit": 10, "offset": 0},
            },
        )
        module_test.second_page_requests = 0

        def plan_limit(request):
            module_test.second_page_requests += 1
            return MockResponse(
                status_code=400,
                json={
                    "errors": [
                        {
                            "id": "pagination_error",
                            "code": 400,
                            "details": "The search results are limited to 10 email addresses on your current plan.",
                        }
                    ]
                },
            )

        module_test.blasthttp_mock.add_callback(plan_limit, url=f"{self.base}&offset=10")

    def check(self, module_test, events):
        assert any(e.data == "asdf@blacklanternsecurity.com" for e in events), "Failed to detect email"
        assert module_test.second_page_requests == 1, "plan-limit error must not be retried"
        assert not module_test.scan.modules["hunterio"].errored
