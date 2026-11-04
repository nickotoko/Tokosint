import json

from .base import ModuleTestBase
from bbot.test.worker import HTTPSERVER_URL
from bbot.modules.internal.validity import FRESHNESS, VERDICT_FALSE

BLS = "blacklanternsecurity.com"


class TestValidity(ModuleTestBase):
    # certspotter — актуальный источник (только неистёкшие серты), crt — исторический (вся CT-история)
    modules_overrides = ["certspotter", "crt"]
    config_overrides = {
        "dns": {"minimal": False},
        "scope": {"report_distance": 1},
        # нерезолвящиеся имена — исторические находки, их должно быть видно в выводе
        "omit_event_types": ["HTTP_RESPONSE", "RAW_TEXT", "URL_UNVERIFIED", "RAW_DNS_RECORD"],
    }

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns(
            {
                BLS: {"A": ["127.0.0.1"]},
                f"live.{BLS}": {"A": ["127.0.0.2"]},
                f"old.{BLS}": {"A": ["127.0.0.3"]},
                f"fake.{BLS}": {"A": ["127.0.0.4"]},
                # висячий CNAME: цель CNAME не резолвится
                f"dangling.{BLS}": {"CNAME": ["gone-saas.example.org"]},
                # stale.* и gone.* в DNS нет
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

        # проверка-заглушка: помечает находку ложной
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

        # не резолвится → историческое, даже от актуального источника
        stale = find(events, "DNS_NAME_UNRESOLVED", f"stale.{BLS}", "certspotter")
        assert {"validity-historical", "freshness-historical", "dns-check-nxdomain"} <= stale.tags
        gone = find(events, "DNS_NAME_UNRESOLVED", f"gone.{BLS}", "crt")
        assert {"validity-historical", "dns-check-nxdomain"} <= gone.tags
        # CNAME без адреса — висячий
        dangling = find(events, "DNS_NAME", f"dangling.{BLS}", "crt")
        assert {"validity-historical", "dns-check-dangling"} <= dangling.tags

        # ложное не попадает в скан и не рекурсирует, но пишется в журнал
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
        # имя цели резолвится → подтверждено сейчас, независимо от источника
        live = find(events, "DNS_NAME", f"live.{BLS}", "certspotter")
        assert {"validity-valid", "freshness-verified", "dns-check-ok"} <= live.tags
        old = find(events, "DNS_NAME", f"old.{BLS}", "crt")
        assert {"validity-valid", "freshness-verified", "dns-check-ok"} <= old.tags
        # потомки подтверждённого имени — валидные
        assert "validity-valid" in find(events, "IP_ADDRESS", "127.0.0.3").tags


class TestValidity_NoPromote(TestValidity):
    """promote_resolved: none — резолв только понижает, правило «исторический родитель» не снимается."""

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
        # живой DNS-резолв исторического имени: свой источник актуален, но родитель исторический
        old_ip = find(events, "IP_ADDRESS", "127.0.0.3")
        assert {"validity-historical", "freshness-current"} <= old_ip.tags


class TestValidity_ModuleFreshness(TestValidity):
    """Каждый модуль, порождающий события, обязан объявить meta["freshness"]."""

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
    """Связь вне скоупа и мусор: чужое имя со страницы скрывается, адреса-заглушки и имена файлов отбрасываются,
    запись DNS цели на внешнего провайдера и внешний контакт остаются."""

    module_name = "validity"
    modules_overrides = []
    # distance 2 — чтобы IP провайдера (A-запись ns1) резолвился и попал в вывод
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
            """Как excavate/host: имена и адреса, найденные на странице цели."""

            _name = "page_links"
            watched_events = ["DNS_NAME"]
            meta = {"freshness": "current"}

            async def handle_event(self, event):
                if event.data != BLS:
                    return
                await self.emit_event("cdn.othercorp.io", "DNS_NAME", parent=event, context="link {event.data}")
                for email in ("hand@3x.png", "user@gmail.com", "email@email.com", "info@othercorp.io"):
                    await self.emit_event(email, "EMAIL_ADDRESS", parent=event, context="email {event.data}")

        module = page_links(module_test.scan)
        await module.setup()
        module_test.scan.modules["page_links"] = module

    def check(self, module_test, events):
        data = {e.data for e in events if isinstance(e.data, str)}
        # внешний контакт и провайдер DNS цели — валидные
        ns = TestValidity.find(events, "DNS_NAME", "ns1.dnsprovider.io", "NS")
        assert {"validity-valid", "third-party"} <= ns.tags
        # IP провайдера — тоже третья сторона; сид и его IP — активы цели
        assert "third-party" in TestValidity.find(events, "IP_ADDRESS", "127.0.0.9").tags
        assert "third-party" not in TestValidity.find(events, "DNS_NAME", BLS, "SEED").tags
        assert "third-party" not in TestValidity.find(events, "IP_ADDRESS", "127.0.0.1").tags
        contact = TestValidity.find(events, "EMAIL_ADDRESS", "info@othercorp.io")
        assert "validity-valid" in contact.tags
        # чужое имя со страницы и мусор — не в выводе
        for junk in ("cdn.othercorp.io", "hand@3x.png", "user@gmail.com", "email@email.com", "127.0.0.8"):
            assert junk not in data, junk

        log = module_test.scan.home / "validity_false.jsonl"
        records = {r["data"]: r for r in (json.loads(x) for x in log.read_text().splitlines())}
        assert records["cdn.othercorp.io"]["hidden"] is True
        assert "without proven relation" in records["cdn.othercorp.io"]["reason"]
        assert records["hand@3x.png"]["hidden"] is False and "no public suffix" in records["hand@3x.png"]["reason"]
        assert "placeholder" in records["user@gmail.com"]["reason"]
        assert "placeholder" in records["email@email.com"]["reason"]
        # скрытый кандидат виден модулям (related_domains), но его потомки не рекурсируют
        assert "127.0.0.8" not in records or records["127.0.0.8"]["hidden"] is False


class TestValidity_HTTP(ModuleTestBase):
    """Ссылки из архива (исторический источник): живой ответ цели → valid (verified), 410 → historical."""

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
            """Как wayback: старые ссылки на ресурсы цели."""

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
