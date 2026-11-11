import platform
import shutil
import sqlite3
import sys
from pathlib import Path

import pytest

from .base import ModuleTestBase
from bbot.test.worker import (
    worker_dir,
    HTTPSERVER_HOSTPORT,
    HTTPSERVER_PORT,
    HTTPSERVER_SSL_PORT,
    HTTPSERVER_SSL_URL,
    HTTPSERVER_URL,
)


def _find(paths):
    return next((str(p) for p in paths if p and Path(p).is_file()), None)


# Integration tests run the real gowitness and Chrome. Scans here run without installing dependencies, so the tests
# use what is installed (BBOT's tools dir, PATH, macOS /Applications) and are skipped when it is not.
GOWITNESS = _find([Path.home() / ".bbot" / "tools" / "gowitness", shutil.which("gowitness")])
CHROME = _find(
    [
        Path.home() / ".bbot/tools/chrome-mac/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" if platform.system() == "Darwin" else None,
        shutil.which("chromium"),
        shutil.which("google-chrome"),
        shutil.which("chrome"),
    ]
)
needs_gowitness = pytest.mark.skipif(not (GOWITNESS and CHROME), reason="gowitness and chrome are not installed")
INSTALLED = {
    "deps": {"behavior": "disable"},
    "modules": {"gowitness": {"binary": GOWITNESS or "", "chrome_path": CHROME or "", "network_urls": True}},
}


class TestGowitnessFake(ModuleTestBase):
    """Always runs: gowitness is replaced by a stub that writes the database the real one would."""

    module_name = "gowitness"
    targets = [f"{HTTPSERVER_URL}/"]
    modules_overrides = ["gowitness", "http"]
    # any executable that answers --version stands in for gowitness and chrome
    config_overrides = {
        "deps": {"behavior": "disable"},
        "omit_event_types": [],
        "modules": {"gowitness": {"binary": sys.executable, "chrome_path": sys.executable}},
    }

    # what the stub "gowitness" does with a page: shot (a row and a file), failed (a row without a file), missing
    # (no row at all - no answer)
    outcome = "shot"

    async def setup_after_prep(self, module_test):
        module_test.set_expect_requests(respond_args={"response_data": "<html><title>hi</title></html>"})
        module = module_test.scan.modules["gowitness"]
        self.commands = []
        outcome = self.outcome

        async def fake_live(command, **kwargs):
            self.commands.append(command)
            db = command[command.index("--write-db-uri") + 1].removeprefix("sqlite://")
            visited = kwargs["input"].splitlines()
            con = sqlite3.connect(db)
            con.execute(
                "CREATE TABLE results (id INTEGER, url TEXT, final_url TEXT, filename TEXT, response_code INTEGER,"
                " title TEXT, failed INTEGER, failed_reason TEXT)"
            )
            con.execute("CREATE TABLE network_logs (result_id INTEGER, url TEXT, status_code INTEGER, remote_ip TEXT)")
            con.execute("CREATE TABLE technologies (result_id INTEGER, value TEXT)")
            for i, url in enumerate(visited, 1):
                if outcome == "missing":
                    continue
                if outcome == "failed":
                    con.execute(
                        "INSERT INTO results VALUES (?, ?, ?, '', 0, '', 1, 'net::ERR_TIMED_OUT')", (i, url, url)
                    )
                    continue
                (module.screenshot_path / f"page{i}.jpeg").write_bytes(b"\xff\xd8\xff")
                con.execute(
                    "INSERT INTO results VALUES (?, ?, ?, ?, 403, 'Forbidden page', 0, '')",
                    (i, url, url, f"page{i}.jpeg"),
                )
                con.execute(
                    "INSERT INTO network_logs VALUES (?, ?, 200, '8.8.8.8')", (i, "https://fonts.example/a.css")
                )
                con.execute("INSERT INTO technologies VALUES (?, 'Nginx')", (i,))
            con.commit()
            con.close()
            yield "done"

        module_test.monkeypatch.setattr(module, "run_process_live", fake_live)
        # what the module emits, before validity drops out-of-scope names
        self.emitted = []
        emit = module.emit_event

        async def record(*args, **kwargs):
            event = args[0]
            self.emitted.append(
                (
                    getattr(event, "type", kwargs.get("event_type") or (args[1] if len(args) > 1 else None)),
                    str(getattr(event, "data", event)),
                )
            )
            return await emit(*args, **kwargs)

        module_test.monkeypatch.setattr(module, "emit_event", record)

    def check(self, module_test, events):
        shots = [e for e in events if e.type == "WEBSCREENSHOT"]
        assert len(shots) == 1 and shots[0].data["url"] == f"{HTTPSERVER_URL}/"
        assert shots[0].data["path"].endswith("gowitness/screenshots/page1.jpeg")
        assert shots[0].parent.type == "URL"
        # the answer the browser got and the page title travel with the screenshot
        assert shots[0].data["status_code"] == 403 and shots[0].data["title"] == "Forbidden page"
        assert module_test.scan.modules["gowitness"].failures == {}
        assert "--log-scan-errors" in self.commands[0]
        assert any(e.type == "TECHNOLOGY" and e.data["technology"] == "nginx" for e in events)
        # the configured binary is what runs
        assert self.commands and self.commands[0][0] == sys.executable
        # by default the URLs the browser loaded while rendering (third-party fonts, CDNs) are not emitted
        assert not any(t == "URL_UNVERIFIED" for t, _ in self.emitted), self.emitted
        assert module_test.scan.modules["gowitness"].meta["freshness"] == "current"


class TestGowitnessFakeNetworkUrls(TestGowitnessFake):
    config_overrides = {
        "deps": {"behavior": "disable"},
        "omit_event_types": [],
        "modules": {"gowitness": {"binary": sys.executable, "chrome_path": sys.executable, "network_urls": True}},
    }

    def check(self, module_test, events):
        # emitted; validity then drops it as an out-of-scope name with no proven relation to the target
        assert any(t == "URL_UNVERIFIED" and "https://fonts.example/a.css" in d for t, d in self.emitted), self.emitted


class TestGowitnessFakeFailed(TestGowitnessFake):
    """A page gowitness could not shoot: no WEBSCREENSHOT pointing at the folder, the reason is counted."""

    outcome = "failed"

    def check(self, module_test, events):
        assert not any(e.type == "WEBSCREENSHOT" for e in events)
        assert module_test.scan.modules["gowitness"].failures == {"net::ERR_TIMED_OUT": 1}


class TestGowitnessFakeNoAnswer(TestGowitnessFake):
    outcome = "missing"

    def check(self, module_test, events):
        assert not any(e.type == "WEBSCREENSHOT" for e in events)
        assert module_test.scan.modules["gowitness"].failures == {"no answer (DNS / connection error or blocked)": 1}


class TestGowitnessRedirects(TestGowitnessFake):
    """A redirect to an in-scope URL is skipped (that URL is shot itself), a redirect elsewhere is shot."""

    async def setup_after_prep(self, module_test):
        await super().setup_after_prep(module_test)
        module = module_test.scan.modules["gowitness"]
        root = module_test.scan.root_event

        def redirect(location):
            e = module_test.scan.make_event(
                {"url": f"{HTTPSERVER_URL}/r", "redirect_location": location}, "URL", parent=root, tags=["status-301"]
            )
            e.scope_distance = 0
            return e

        self.inside = await module.filter_event(redirect(f"{HTTPSERVER_URL}/next"))
        self.outside = await module.filter_event(redirect("https://ddos-guard.example/check"))

    def check(self, module_test, events):
        assert self.inside[0] is False and "in-scope" in self.inside[1]
        assert self.outside is True


class TestGowitnessMissing(ModuleTestBase):
    """No gowitness: the module turns itself off, the scan goes on."""

    module_name = "gowitness"
    modules_overrides = ["gowitness"]
    config_overrides = {
        "deps": {"behavior": "disable"},
        "modules": {"gowitness": {"binary": "/nonexistent/gowitness"}},
    }

    def check(self, module_test, events):
        assert "gowitness" not in module_test.scan.modules
        assert any(e.type == "SCAN" for e in events)


@needs_gowitness
class TestGowitness(ModuleTestBase):
    targets = [HTTPSERVER_HOSTPORT]
    modules_overrides = ["gowitness", "http", "social", "excavate"]
    import shutil
    from pathlib import Path

    home_dir = worker_dir("/tmp/.bbot_gowitness_test")
    shutil.rmtree(home_dir, ignore_errors=True)
    config_overrides = {
        **INSTALLED,
        "home": str(home_dir),
        "scope": {"report_distance": 2},
        "omit_event_types": [],
    }

    async def setup_after_prep(self, module_test):
        respond_args = {
            "response_data": """<html><head><title>BBOT is life</title></head><body>
<link href="https://github.com/blacklanternsecurity">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Open+Sans+Condensed:wght@700&family=Open+Sans:ital,wght@0,400;0,600;0,700;0,800;1,400&display=swap" rel="stylesheet">
</body></html>""",
            "headers": {"Server": "Apache/2.4.41 (Ubuntu)"},
        }
        module_test.set_expect_requests(respond_args=respond_args)
        request_args = {"uri": "/blacklanternsecurity"}
        respond_args = {"response_data": """blacklanternsecurity github <a data-bem"""}
        module_test.set_expect_requests(request_args, respond_args)

        # monkeypatch social
        old_emit_event = module_test.scan.modules["social"].emit_event

        async def new_emit_event(event, **kwargs):
            if event.data["url"] == "https://github.com/blacklanternsecurity":
                event.data["url"] = event.data["url"].replace("https://github.com", HTTPSERVER_URL)
                event.parsed_url = module_test.scan.helpers.urlparse(event.data["url"])
            await old_emit_event(event, **kwargs)

        module_test.monkeypatch.setattr(module_test.scan.modules["social"], "emit_event", new_emit_event)

    def check(self, module_test, events):
        webscreenshots = [e for e in events if e.type == "WEBSCREENSHOT"]
        assert webscreenshots, "failed to raise WEBSCREENSHOT events"
        assert not any("blob" in e.data for e in webscreenshots), (
            "blob was included in WEBSCREENSHOT data when it shouldn't have been"
        )

        screenshots_path = self.home_dir / "scans" / module_test.scan.name / "gowitness" / "screenshots"
        screenshots = list(screenshots_path.glob("*.jpeg"))
        assert len(screenshots) == 1, (
            f"{len(screenshots):,} .jpeg files found at {screenshots_path}, should have been 1"
        )
        assert 1 == len([e for e in events if e.type == "URL" and e.url == f"{HTTPSERVER_URL}/"])
        assert 1 == len([e for e in events if e.type == "URL_UNVERIFIED" and e.url == "https://fonts.googleapis.com/"])
        assert 0 == len([e for e in events if e.type == "URL" and e.url == "https://fonts.googleapis.com/"])
        assert 1 == len(
            [e for e in events if e.type == "SOCIAL" and e.data["url"] == f"{HTTPSERVER_URL}/blacklanternsecurity"]
        )
        assert 1 == len([e for e in events if e.type == "WEBSCREENSHOT"])
        assert 1 == len([e for e in events if e.type == "WEBSCREENSHOT" and e.data["url"] == f"{HTTPSERVER_URL}/"])
        assert len([e for e in events if e.type == "TECHNOLOGY"])


class TestGowitness_Social(TestGowitness):
    config_overrides = dict(TestGowitness.config_overrides)
    config_overrides.update({"modules": {"gowitness": {**INSTALLED["modules"]["gowitness"], "social": True}}})

    def check(self, module_test, events):
        screenshots_path = self.home_dir / "scans" / module_test.scan.name / "gowitness" / "screenshots"
        screenshots = list(screenshots_path.glob("*.jpeg"))
        assert len(screenshots) == 2, (
            f"{len(screenshots):,} .jpeg files found at {screenshots_path}, should have been 2"
        )
        assert 2 == len([e for e in events if e.type == "WEBSCREENSHOT"])
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "WEBSCREENSHOT" and e.data["url"] == f"{HTTPSERVER_URL}/blacklanternsecurity"
            ]
        )
        assert len(
            [
                e
                for e in events
                if e.type == "TECHNOLOGY"
                and e.data["url"] == f"{HTTPSERVER_URL}/blacklanternsecurity"
                and e.parent.type == "SOCIAL"
            ]
        )


class TestGoWitnessWithBlob(TestGowitness):
    config_overrides = {**INSTALLED, "file_blobs": True}

    def check(self, module_test, events):
        webscreenshots = [e for e in events if e.type == "WEBSCREENSHOT"]
        assert webscreenshots, "failed to raise WEBSCREENSHOT events"
        assert all("blob" in e.data and e.data["blob"] for e in webscreenshots), "blob not found in WEBSCREENSHOT data"


class TestGoWitnessLongFilename(TestGowitness):
    """
    Make sure long filenames are truncated properly
    """

    targets = [
        f"{HTTPSERVER_URL}/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity"
    ]
    config_overrides = {**INSTALLED, "file_blobs": True}

    async def setup_after_prep(self, module_test):
        request_args = {
            "uri": "/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity/blacklanternsecurity"
        }
        respond_args = {
            "response_data": "<html><head><title>BBOT is life</title></head><body>BBOT is life</body></html>",
            "headers": {"Server": "Apache/2.4.41 (Ubuntu)"},
        }
        module_test.set_expect_requests(request_args, respond_args)

    def check(self, module_test, events):
        # the event points at the file gowitness actually saved (a name truncated by BBOT would not open)
        webscreenshots = [e for e in events if e.type == "WEBSCREENSHOT"]
        assert len(webscreenshots) == 1
        assert (module_test.scan.home / webscreenshots[0].data["path"]).is_file()


@needs_gowitness
class TestGowitness_MultiPort(ModuleTestBase):
    """
    Integration test: two URLs on the same host with different ports
    (one HTTP, one HTTPS) both get correctly correlated screenshots.
    Exercises the real gowitness binary and _resolve_parent tiered lookup.
    """

    targets = [HTTPSERVER_URL, HTTPSERVER_SSL_URL]
    modules_overrides = ["gowitness", "http"]

    import shutil

    home_dir = worker_dir("/tmp/.bbot_gowitness_multiport_test")
    shutil.rmtree(home_dir, ignore_errors=True)
    config_overrides = {
        **INSTALLED,
        "home": str(home_dir),
        "omit_event_types": [],
    }

    async def setup_after_prep(self, module_test):
        # plain HTTP server
        module_test.set_expect_requests(
            respond_args={
                "response_data": f"<html><head><title>Port {HTTPSERVER_PORT}</title></head><body>Port {HTTPSERVER_PORT}</body></html>",
                "headers": {"Server": "Apache/2.4.41"},
            },
        )
        # TLS server
        module_test.httpserver_ssl.expect_request("/").respond_with_data(
            f"<html><head><title>Port {HTTPSERVER_SSL_PORT}</title></head><body>Port {HTTPSERVER_SSL_PORT}</body></html>",
            headers={"Server": "nginx/1.18.0"},
        )

    def check(self, module_test, events):
        webscreenshots = [e for e in events if e.type == "WEBSCREENSHOT"]
        assert len(webscreenshots) >= 2, f"Expected at least 2 WEBSCREENSHOT events, got {len(webscreenshots)}"

        screenshot_urls = {e.data["url"] for e in webscreenshots}
        http_port, ssl_port = str(HTTPSERVER_PORT), str(HTTPSERVER_SSL_PORT)
        assert any(http_port in url for url in screenshot_urls), (
            f"No screenshot for port {http_port}. URLs: {screenshot_urls}"
        )
        assert any(ssl_port in url for url in screenshot_urls), (
            f"No screenshot for port {ssl_port}. URLs: {screenshot_urls}"
        )

        # Verify parent events reference the correct port
        for ws in webscreenshots:
            url = ws.data["url"]
            parent = ws.parent
            if http_port in url:
                assert http_port in str(parent.data), f"Screenshot for :{http_port} has wrong parent: {parent.data}"
            elif ssl_port in url:
                assert ssl_port in str(parent.data), f"Screenshot for :{ssl_port} has wrong parent: {parent.data}"
