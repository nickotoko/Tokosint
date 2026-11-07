import json

from .base import ModuleTestBase
from bbot.test.worker import HTTPSERVER_URL
from bbot.modules.internal.validity import FRESHNESS, VERDICT_FALSE

BLS = "blacklanternsecurity.com"


class TestValidity(ModuleTestBase):
    # certspotter is a current source (unexpired certificates only), crt is historical (the whole CT history)
    modules_overrides = ["certspotter", "crt"]
    config_overrides = {
        "dns": {"minimal": False},
        "scope": {"report_distance": 1},
        # names that do not resolve are historical findings and must be visible in the output
        "omit_event_types": ["HTTP_RESPONSE", "RAW_TEXT", "URL_UNVERIFIED", "RAW_DNS_RECORD"],
    }

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                BLS: {"A": ["127.0.0.1"]},
                f"live.{BLS}": {"A": ["127.0.0.2"]},
                f"old.{BLS}": {"A": ["127.0.0.3"]},
                f"fake.{BLS}": {"A": ["127.0.0.4"]},
                # dangling CNAME: the CNAME target does not resolve
                f"dangling.{BLS}": {"CNAME": ["gone-saas.example.org"]},
                # stale.* and gone.* are not in DNS
            }
        )
        module_test.blasthttp_mock.add_response(
            url=f"https://api.certspotter.com/v1/issuances?domain={BLS}&include_subdomains=true&expand=dns_names",
            json=[{"dns_names": [f"live.{BLS}", f"stale.{BLS}"]}],
        )
        module_test.blasthttp_mock.add_response(
            url=f"https://crt.sh?q=%25.{BLS}&output=json",
            json=[{"id": 1, "name_value": f"old.{BLS}\nfake.{BLS}\ngone.{BLS}\ndangling.{BLS}"}],
        )
        for name in ("certspotter", "crt"):
            module_test.scan.modules[name].abort_if = lambda e: False

        # stub check: marks a finding as false
        def fake_check(event):
            if event.host == f"fake.{BLS}":
                return VERDICT_FALSE, "test: fake"

        module_test.scan.modules["validity"].checks.append(fake_check)

    @staticmethod
    def find(events, etype, data, module=None):
        found = [e for e in events if e.type == etype and e.data == data]
        if module:
            found = [e for e in found if str(e.module) == module]
        assert found, f"{etype} {data} ({module}) not found"
        return found[0]

    def check_common(self, module_test, events):
        find = self.find
        assert "validity-valid" in find(events, "DNS_NAME", BLS, "SEED").tags

        # does not resolve -> historical, even from a current source
        stale = find(events, "DNS_NAME_UNRESOLVED", f"stale.{BLS}", "certspotter")
        assert {"validity-historical", "freshness-historical", "dns-check-nxdomain"} <= stale.tags
        gone = find(events, "DNS_NAME_UNRESOLVED", f"gone.{BLS}", "crt")
        assert {"validity-historical", "dns-check-nxdomain"} <= gone.tags
        # CNAME without an address is dangling
        dangling = find(events, "DNS_NAME", f"dangling.{BLS}", "crt")
        assert {"validity-historical", "dns-check-dangling"} <= dangling.tags

        # a false finding is not passed to the scan and does not recurse, but is logged
        assert not any(e.data == f"fake.{BLS}" for e in events)
        assert not any(e.data == "127.0.0.4" for e in events)
        log = module_test.scan.home / "validity_false.jsonl"
        records = [json.loads(line) for line in log.read_text().splitlines()]
        assert any(r["data"] == f"fake.{BLS}" and r["reason"] == "test: fake" for r in records)

        for e in events:
            if e.type != "SCAN":
                assert any(t.startswith("validity-") for t in e.tags), e

    def check(self, module_test, events):
        self.check_common(module_test, events)
        find = self.find
        # a target name that resolves -> confirmed now, whatever the source
        live = find(events, "DNS_NAME", f"live.{BLS}", "certspotter")
        assert {"validity-valid", "freshness-verified", "dns-check-ok"} <= live.tags
        old = find(events, "DNS_NAME", f"old.{BLS}", "crt")
        assert {"validity-valid", "freshness-verified", "dns-check-ok"} <= old.tags
        # descendants of a confirmed name are valid
        assert "validity-valid" in find(events, "IP_ADDRESS", "127.0.0.3").tags


class TestValidity_NoPromote(TestValidity):
    """promote_resolved: none - resolution only demotes; the historical-parent rule is not lifted."""

    config_overrides = {
        **TestValidity.config_overrides,
        "modules": {"validity": {"promote_resolved": "none"}},
    }

    def check(self, module_test, events):
        self.check_common(module_test, events)
        find = self.find
        live = find(events, "DNS_NAME", f"live.{BLS}", "certspotter")
        assert {"validity-valid", "freshness-current", "dns-check-ok"} <= live.tags
        old = find(events, "DNS_NAME", f"old.{BLS}", "crt")
        assert {"validity-historical", "freshness-historical", "dns-check-ok"} <= old.tags
        # live DNS resolution of a historical name: its own source is current, but the parent is historical
        old_ip = find(events, "IP_ADDRESS", "127.0.0.3")
        assert {"validity-historical", "freshness-current"} <= old_ip.tags


class TestValidity_ModuleFreshness(TestValidity):
    """Every module that produces events must declare meta["freshness"]."""

    def check(self, module_test, events):
        from bbot.core.modules import MODULE_LOADER

        missing = {}
        for name, preloaded in MODULE_LOADER.preloaded().items():
            if preloaded["type"] == "output" or not preloaded["produced_events"]:
                continue
            level = preloaded["meta"].get("freshness")
            if level not in FRESHNESS:
                missing[name] = level
        assert not missing, f"modules without valid meta freshness: {missing}"


class TestValidity_RelationsAndJunk(ModuleTestBase):
    """Out-of-scope relations and junk: a foreign name from a page is hidden, placeholder emails and file names are dropped,
    a target DNS record pointing to an external provider and an external contact are kept."""

    module_name = "validity"
    modules_overrides = []
    # distance 2, so the provider IP (ns1's A record) resolves and reaches the output
    config_overrides = {"dns": {"minimal": False, "search_distance": 2}, "scope": {"report_distance": 2}}

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                BLS: {"A": ["127.0.0.1"], "NS": ["ns1.dnsprovider.io."]},
                "ns1.dnsprovider.io": {"A": ["127.0.0.9"]},
                "cdn.othercorp.io": {"A": ["127.0.0.8"]},
            }
        )
        from bbot.modules.base import BaseModule

        class page_links(BaseModule):
            """Like excavate/host: names and emails found on a target page."""

            _name = "page_links"
            watched_events = ["DNS_NAME"]
            meta = {"freshness": "current"}

            async def handle_event(self, event):
                if event.data != BLS:
                    return
                await self.emit_event("cdn.othercorp.io", "DNS_NAME", parent=event, context="link {event.data}")
                # a search module reporting ports directly (not through the name): a foreign host and the target
                for netloc in ("shop.othercorp.io:443", f"api.{BLS}:8443"):
                    await self.emit_event(netloc, "OPEN_TCP_PORT", parent=event, context="port {event.data}")
                # BBoT's placeholder of a wildcard domain
                await self.emit_event(f"_wildcard.{BLS}", "DNS_NAME", parent=event, context="wildcard {event.data}")
                for email in ("hand@3x.png", "user@gmail.com", "email@email.com", "info@othercorp.io"):
                    await self.emit_event(email, "EMAIL_ADDRESS", parent=event, context="email {event.data}")

        module = page_links(module_test.scan)
        await module.setup()
        module_test.scan.modules["page_links"] = module

    def check(self, module_test, events):
        data = {e.data for e in events if isinstance(e.data, str)}
        # an external contact and the target's DNS provider are valid
        ns = TestValidity.find(events, "DNS_NAME", "ns1.dnsprovider.io", "NS")
        assert {"validity-valid", "third-party"} <= ns.tags
        # the provider IP is third-party too; the seed and its IP are target assets
        assert "third-party" in TestValidity.find(events, "IP_ADDRESS", "127.0.0.9").tags
        assert "third-party" not in TestValidity.find(events, "DNS_NAME", BLS, "SEED").tags
        assert "third-party" not in TestValidity.find(events, "IP_ADDRESS", "127.0.0.1").tags
        contact = TestValidity.find(events, "EMAIL_ADDRESS", "info@othercorp.io")
        assert "validity-valid" in contact.tags
        # a foreign name from the page and junk are not in the output
        for junk in ("cdn.othercorp.io", "hand@3x.png", "user@gmail.com", "email@email.com", "127.0.0.8"):
            assert junk not in data, junk

        log = module_test.scan.home / "validity_false.jsonl"
        records = {r["data"]: r for r in (json.loads(x) for x in log.read_text().splitlines())}
        assert records["cdn.othercorp.io"]["hidden"] is True
        assert "without proven relation" in records["cdn.othercorp.io"]["reason"]
        assert records["hand@3x.png"]["hidden"] is False and "no public suffix" in records["hand@3x.png"]["reason"]
        assert "placeholder" in records["user@gmail.com"]["reason"]
        assert "placeholder" in records["email@email.com"]["reason"]
        # a port on a foreign host from a search is false; a port on a target name is kept
        assert "shop.othercorp.io:443" not in data
        assert "out-of-scope host" in records["shop.othercorp.io:443"]["reason"]
        assert f"api.{BLS}:8443" in data
        # the wildcard placeholder is not a host
        assert f"_wildcard.{BLS}" not in data
        assert "wildcard placeholder" in records[f"_wildcard.{BLS}"]["reason"]
        # the hidden candidate is visible to modules (related_domains), but its descendants do not recurse
        assert "127.0.0.8" not in records or records["127.0.0.8"]["hidden"] is False


class TestValidity_HTTP(ModuleTestBase):
    """Links from an archive (historical source): a live target answer -> valid (verified), 410 -> historical."""

    module_name = "validity"
    targets = [HTTPSERVER_URL]
    modules_overrides = ["http"]

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/"}, respond_args={"response_data": "home"}
        )
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/live"}, respond_args={"response_data": "alive"}
        )
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/removed"}, respond_args={"response_data": "gone", "status": 410}
        )
        from bbot.modules.base import BaseModule

        class archive(BaseModule):
            """Like wayback: old links to target resources."""

            _name = "archive"
            watched_events = ["URL"]
            meta = {"freshness": "historical"}

            async def handle_event(self, event):
                if event.parsed_url.path != "/":
                    return
                for path in ("live", "removed"):
                    await self.emit_event(
                        f"{HTTPSERVER_URL}/{path}", "URL_UNVERIFIED", parent=event, context="archived {event.data}"
                    )

        module = archive(module_test.scan)
        await module.setup()
        module_test.scan.modules["archive"] = module

    def check(self, module_test, events):
        urls = {e.url: e for e in events if e.type == "URL"}
        live = urls[f"{HTTPSERVER_URL}/live"]
        assert {"validity-valid", "freshness-verified", "status-200"} <= live.tags
        removed = urls[f"{HTTPSERVER_URL}/removed"]
        assert {"validity-historical", "status-410"} <= removed.tags


def _seed_status_file():
    import tempfile

    fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump({f"old.{BLS}": "historical", BLS: "valid"}, fh)
    fh.close()
    return fh.name


class TestValidity_SeedStatus(ModuleTestBase):
    """A scan enriching an earlier one: seeds keep the status they had there, and their descendants follow it."""

    module_name = "validity"
    modules_overrides = []
    targets = [BLS, f"old.{BLS}"]
    config_overrides = {
        "dns": {"minimal": False},
        "scope": {"report_distance": 1},
        "modules": {"validity": {"seed_status_file": _seed_status_file()}},
    }

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns({BLS: {"A": ["127.0.0.1"]}, f"old.{BLS}": {"A": ["127.0.0.3"]}})

    def check(self, module_test, events):
        old = TestValidity.find(events, "DNS_NAME", f"old.{BLS}")
        assert {"seed", "validity-historical", "freshness-historical"} <= old.tags, old.tags
        seed = TestValidity.find(events, "DNS_NAME", BLS)
        assert "validity-valid" in seed.tags
        # the live A record of a historical seed: current source, historical parent
        assert "validity-historical" in TestValidity.find(events, "IP_ADDRESS", "127.0.0.3").tags
