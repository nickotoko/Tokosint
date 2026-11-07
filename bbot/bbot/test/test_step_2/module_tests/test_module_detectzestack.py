from .base import ModuleTestBase

BLS = "blacklanternsecurity.com"
AUTH = {"X-API-Key": "asdf"}


def result(domain, technologies, cached=False, depth="full"):
    return {"url": f"https://{domain}", "domain": domain, "technologies": technologies, "cached": cached,
            "meta": {"status_code": 200, "tech_count": len(technologies), "scan_depth": depth}}  # fmt: skip


class TestDetectZeStack(ModuleTestBase):
    targets = [BLS, f"www.{BLS}", f"nothing.{BLS}"]
    config_overrides = {"modules": {"detectzestack": {"api_key": "asdf"}}}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns({BLS: {"A": ["127.0.0.88"]}, f"www.{BLS}": {"A": ["127.0.0.88"]}})

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url="https://detectzestack.com/stats", match_headers=AUTH,
            json={"tier": "basic", "used": 3, "limit": 100, "remaining": 97},
        )  # fmt: skip
        module_test.blasthttp_mock.add_response(
            url="https://detectzestack.com/analyze/batch",
            method="POST",
            match_headers=AUTH,
            json={
                "results": [
                    {"url": BLS, "result": result(BLS, [
                        {"name": "Nginx", "version": "1.25.3", "categories": ["Web servers"], "confidence": 100,
                         "source": "http"},
                        {"name": "Google Workspace", "categories": ["Email"], "confidence": 100, "source": "dns"},
                        {"name": "Maybe-CMS", "categories": ["CMS"], "confidence": 20, "source": "wappalyzer"},
                    ])},
                    {"url": f"www.{BLS}", "result": result(f"www.{BLS}", [
                        {"name": "React", "categories": ["JavaScript frameworks"], "confidence": 100, "source": "http"},
                    ], cached=True)},
                ],
                "successful": 2,
                "failed": 0,
            },
        )  # fmt: skip

    def check(self, module_test, events):
        tech = {(e.data["host"], e.data["technology"]): e for e in events if e.type == "TECHNOLOGY"}
        assert (BLS, "nginx 1.25.3") in tech, tech
        nginx = tech[(BLS, "nginx 1.25.3")]
        assert nginx.data["url"] == f"https://{BLS}/"
        assert "Web servers, via http, confidence 100" in nginx.discovery_context
        assert nginx.parent.data == BLS
        assert (BLS, "google workspace") in tech, "dns layer is kept by default"
        assert (BLS, "maybe-cms") not in tech, "below min_confidence"
        assert (f"www.{BLS}", "react") in tech
        # a name without an address is not sent
        assert not any(e.type == "TECHNOLOGY" and e.data["host"] == f"nothing.{BLS}" for e in events)
        module = module_test.scan.modules["detectzestack"]
        # the cached answer does not count against the per-scan budget
        assert module.fresh_lookups == 1


class TestDetectZeStack_LayersAndBudget(TestDetectZeStack):
    module_name = "detectzestack"
    config_overrides = {"modules": {"detectzestack": {"api_key": "asdf", "layers": ["http"], "max_lookups": 1}}}

    def check(self, module_test, events):
        tech = {(e.data["host"], e.data["technology"]) for e in events if e.type == "TECHNOLOGY"}
        # max_lookups=1 counts fresh scans only: the cached answer (www) is given back to the budget
        assert module_test.scan.modules["detectzestack"].fresh_lookups <= 1
        if any(h == BLS for h, _ in tech):
            assert (BLS, "nginx 1.25.3") in tech
            assert (BLS, "google workspace") not in tech, "dns layer filtered out"


class TestDetectZeStack_QuotaExhausted(ModuleTestBase):
    module_name = "detectzestack"
    targets = [BLS]
    config_overrides = {"modules": {"detectzestack": {"api_key": "asdf"}}}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns({BLS: {"A": ["127.0.0.88"]}})

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(url="https://detectzestack.com/stats", json={"tier": "basic"})
        module_test.blasthttp_mock.add_response(
            url="https://detectzestack.com/analyze/batch", method="POST", status_code=429,
            json={"error": "monthly limit reached", "limit": 100, "used": 100, "tier": "basic"},
        )  # fmt: skip

    def check(self, module_test, events):
        assert not any(e.type == "TECHNOLOGY" for e in events)
        assert module_test.scan.modules["detectzestack"].quota_exhausted is True


class TestDetectZeStack_Demo(ModuleTestBase):
    """Without a key: the public /demo endpoint, one URL per request, no auth header."""

    module_name = "detectzestack"
    targets = [BLS]

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns({BLS: {"A": ["127.0.0.88"]}})

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(
            url=f"https://detectzestack.com/demo?url={BLS}",
            json=result(BLS, [
                {"name": "Sectigo", "categories": ["SSL/TLS certificate authority"], "confidence": 70, "source": "tls"},
            ]),
        )  # fmt: skip

    def check(self, module_test, events):
        tech = {(e.data["host"], e.data["technology"]) for e in events if e.type == "TECHNOLOGY"}
        # the tls layer (not in the published enum) is kept: all layers by default
        assert tech == {(BLS, "sectigo")}, tech
        module = module_test.scan.modules["detectzestack"]
        assert module.demo is True and module.max_lookups == module.demo_limit


class TestDetectZeStack_BadKey(TestDetectZeStack_Demo):
    """A refused key (e.g. a URL pasted instead of the key): the module falls back to /demo instead of turning off."""

    config_overrides = {"modules": {"detectzestack": {"api_key": "https://detectzestack.com/dashboard"}}}

    async def setup_before_prep(self, module_test):
        await super().setup_before_prep(module_test)
        module_test.blasthttp_mock.add_response(
            url="https://detectzestack.com/stats", status_code=401, json={"error": "invalid API key"}
        )


class TestDetectZeStack_Chunks(ModuleTestBase):
    """More events than one request takes: chunks of at most 10; the budget is reserved before sending (a request
    lost to a timeout is charged too), so no more than max_lookups URLs are ever sent; requests are never retried."""

    module_name = "detectzestack"
    targets = [BLS]
    config_overrides = {"modules": {"detectzestack": {"api_key": "asdf", "max_lookups": 30}}}

    async def setup_before_prep(self, module_test):
        module_test.blasthttp_mock.add_response(url="https://detectzestack.com/stats", json={"tier": "free"})

    async def setup_after_prep(self, module_test):
        module = module_test.scan.modules["detectzestack"]
        sent = []

        async def lookup_batch(events):
            sent.append(len(events))

        module.lookup_batch = lookup_batch
        root = module_test.scan.root_event
        names = [module.make_event(f"h{i}.{BLS}", "DNS_NAME", parent=root) for i in range(35)]
        await module.handle_batch(*names[:25])
        await module.handle_batch(*names[25:])
        self.sent = sent
        self.retries = module.api_retries

    def check(self, module_test, events):
        assert self.sent == [10, 10, 5, 5], self.sent
        assert self.retries == 1
