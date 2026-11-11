import os
import sys
import asyncio
import aiosqlite
import multiprocessing
import platform
from pathlib import Path

from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field


class gowitness(BaseModule):
    watched_events = ["URL", "SOCIAL"]
    produced_events = ["WEBSCREENSHOT", "URL", "URL_UNVERIFIED", "TECHNOLOGY"]
    flags = ["safe", "active", "web-screenshots"]
    meta = {
        # a screenshot shows the page as it is now
        "freshness": "current",
        "description": "Take screenshots of webpages",
        "created_date": "2022-07-08",
        "author": "@TheTechromancer",
    }

    class Config(BaseModuleConfig):
        version: str = Field("3.1.1", description="Gowitness version")
        threads: int = Field(0, description="How many gowitness threads to spawn (default is number of CPUs x 2)")
        # pages behind anti-DDoS / JS challenges take a while: 10 s lost many of them
        timeout: int = Field(30, description="Seconds before a page counts as timed out")
        resolution_x: int = Field(1440, description="Screenshot resolution x")
        resolution_y: int = Field(900, description="Screenshot resolution y")
        output_path: str = Field("", description="Where to save screenshots")
        social: bool = Field(False, description="Whether to screenshot social media webpages")
        idle_timeout: int = Field(
            1800, description="Skip the current gowitness batch if it stalls for longer than this many seconds"
        )
        chrome_path: str = Field("", description="Path to chrome executable")
        binary: str = Field(
            "", description="Path to the gowitness executable (default: BBOT's tools dir, then gowitness in PATH)"
        )
        network_urls: bool = Field(
            False,
            description="Emit the URLs the browser loaded while rendering a page (fonts, analytics, CDNs: mostly "
            "third-party) as URL_UNVERIFIED",
        )

    deps_common = ["chromium"]
    deps_pip = ["aiosqlite"]
    deps_ansible = [
        {
            "name": "Download gowitness",
            "get_url": {
                "url": "https://github.com/sensepost/gowitness/releases/download/#{BBOT_MODULES_GOWITNESS_VERSION}/gowitness-#{BBOT_MODULES_GOWITNESS_VERSION}-#{BBOT_OS_PLATFORM}-#{BBOT_CPU_ARCH_GOLANG}",
                "dest": "#{BBOT_TOOLS}/gowitness",
                "mode": "755",
            },
        },
    ]
    _batch_size = 100
    # gowitness accepts SOCIAL events up to distance 2, otherwise it is in-scope-only
    scope_distance_modifier = 2

    async def setup(self):
        num_cpus = multiprocessing.cpu_count()
        default_thread_count = min(20, num_cpus * 2)
        self.timeout = self.config.get("timeout", 10)
        self.idle_timeout = self.config.get("idle_timeout", 1800)
        self.threads = self.config.get("threads", 0)
        if not self.threads:
            self.threads = default_thread_count
        self.proxy = self.scan.web_config.get("http_proxy", "")
        self.resolution_x = self.config.get("resolution_x")
        self.resolution_y = self.config.get("resolution_y")
        self.visit_social = self.config.get("social", True)
        self.network_urls = self.config.get("network_urls", False)
        # pages gowitness could not shoot: reason -> count (reported at the end of the scan)
        self.failures = {}
        self.binary = self._find_binary()
        if self.binary is None:
            # soft fail: the rest of the scan goes on without screenshots
            return (
                None,
                "gowitness not found: install it (e.g. `go install github.com/sensepost/gowitness@latest`) or set `binary`",
            )
        output_path = self.config.get("output_path")
        if output_path:
            self.base_path = Path(output_path) / "gowitness"
        else:
            self.base_path = self.scan.home / "gowitness"

        self.chrome_path = None
        config_chrome_path = self.config.get("chrome_path")
        if config_chrome_path:
            config_chrome_path = Path(config_chrome_path)
            if not config_chrome_path.is_file():
                return False, f"Could not find custom Chrome path at {config_chrome_path}"
            self.chrome_path = config_chrome_path
        else:
            if platform.system() == "Darwin":
                bbot_chrome_path = (
                    self.helpers.tools_dir / "chrome-mac" / "Chromium.app" / "Contents" / "MacOS" / "Chromium"
                )
            else:
                bbot_chrome_path = self.helpers.tools_dir / "chrome-linux" / "chrome"
            if bbot_chrome_path.is_file():
                self.chrome_path = bbot_chrome_path

        # make sure our chrome path works
        chrome_test_pass = False
        if self.chrome_path and self.chrome_path.is_file():
            chrome_test_proc = await self.run_process([str(self.chrome_path), "--version"])
            if getattr(chrome_test_proc, "returncode", 1) == 0:
                self.verbose(f"Found chrome executable at {self.chrome_path}")
                chrome_test_pass = True

        if not chrome_test_pass:
            # last resort - try to find a working chrome install (macOS keeps it in /Applications, not in PATH)
            candidates = [self.helpers.which(b) for b in ("Google Chrome", "chrome", "chromium", "chromium-browser")]
            if platform.system() == "Darwin":
                candidates += [
                    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                    "/Applications/Chromium.app/Contents/MacOS/Chromium",
                ]
            for binary_path in candidates:
                if binary_path and Path(binary_path).is_file():
                    chrome_test_proc = await self.run_process([str(binary_path), "--version"])
                    if getattr(chrome_test_proc, "returncode", 1) == 0:
                        self.verbose(f"Found chrome executable at {binary_path}")
                        self.chrome_path = Path(binary_path)
                        chrome_test_pass = True
                        break

        if not chrome_test_pass:
            return (
                None,
                "Failed to set up Google chrome. Please install manually and set `chrome_path`, or try again with --force-deps.",
            )

        # fix ubuntu-specific sandbox bug
        chrome_devel_sandbox = self.helpers.tools_dir / "chrome-linux" / "chrome_sandbox"
        if chrome_devel_sandbox.is_file():
            os.environ["CHROME_DEVEL_SANDBOX"] = str(chrome_devel_sandbox)

        self.screenshot_path = self.base_path / "screenshots"
        self.helpers.mkdir(self.screenshot_path)
        self.screenshot_count = 0
        return True

    def _find_binary(self):
        configured = self.config.get("binary", "")
        if configured:
            return configured if Path(configured).is_file() else None
        bundled = self.helpers.tools_dir / "gowitness"
        if bundled.is_file():
            return str(bundled)
        return self.helpers.which("gowitness")

    async def filter_event(self, event):
        # A redirect to an in-scope URL is skipped: that URL is visited (and shot) itself. A redirect elsewhere - to
        # an anti-DDoS page, a login portal of another domain, no location - is shot: the browser follows it and
        # the picture is what a visitor of the target URL sees.
        if any(t.startswith("status-30") for t in event.tags):
            location = getattr(event, "redirect_location", "") if event.type == "URL" else ""
            if location:
                try:
                    in_scope = self.scan.in_scope(self.helpers.urlparse(location).hostname or "")
                except Exception:
                    in_scope = False
                if in_scope:
                    return False, "URL is a redirect to an in-scope URL"
        # ignore events from self
        if event.type == "URL" and event.module == self:
            return False, "event is from self"
        if event.type == "SOCIAL":
            if not self.visit_social:
                return False, "visit_social=False"
        else:
            # Accept out-of-scope SOCIAL pages, but not URLs
            if event.scope_distance > 0:
                return False, "event is not in-scope"
        return True

    @staticmethod
    def _url_key(parsed_url):
        """Scheme-and-port-agnostic key for URL correlation.

        Gowitness may change both the scheme and port of a URL it visits
        (e.g. recording http://host:443/ for an input of http://host/ when
        the server redirects to HTTPS). We key only by hostname + path so
        correlation succeeds regardless of scheme/port differences.
        """
        hostname = parsed_url.hostname or ""
        path = parsed_url.path or "/"
        return f"{hostname}{path}"

    def _resolve_parent(self, db_url):
        """Match a URL from the gowitness DB back to the original input event.

        Tries exact match first, then falls back to a scheme-and-port-agnostic
        lookup for cases where gowitness transforms the stored URL (e.g. after
        a redirect from http to https).
        """
        parent = self._event_dict.get(db_url)
        if parent is None:
            parent = self._event_dict_loose.get(self._url_key(self.helpers.urlparse(db_url)))
        return parent

    async def handle_batch(self, *events):
        # Each batch gets its own throwaway database. Nothing is persisted once the
        # batch's events are emitted, which keeps memory flat regardless of scan size
        # (gowitness's network_logs table grows enormous on large scans otherwise).
        db_path = self.scan.temp_dir / f"gowitness_{self.helpers.rand_string()}.sqlite3"
        self._event_dict = {}
        self._event_dict_loose = {}
        stdin_urls = []
        for e in events:
            url = e.url if e.type == "SOCIAL" else (e.url or e.data)
            stdin_urls.append(url)
            self._event_dict[url] = e
            self._event_dict_loose.setdefault(self._url_key(self.helpers.urlparse(url)), e)
        stdin = "\n".join(stdin_urls)

        try:
            try:
                async for line in self.run_process_live(
                    self.construct_command(db_path), input=stdin, idle_timeout=self.idle_timeout
                ):
                    self.debug(line)
            except asyncio.exceptions.TimeoutError:
                urls_str = ",".join(self._event_dict)
                self.warning(f"Gowitness timed out while visiting the following URLs: {urls_str}", trace=False)
                return

            try:
                await self.emit_results(db_path)
            except aiosqlite.Error as e:
                # gowitness exited before writing a usable database (chrome likely failed to
                # launch), so the whole batch produced nothing
                self.warning(
                    f"Gowitness produced no results for {len(events)} URLs; chrome may have failed to launch ({e})",
                    trace=False,
                )
        finally:
            # discard the batch database; the screenshots themselves live on disk
            db_path.unlink(missing_ok=True)

    async def emit_results(self, db_path):
        if not db_path.is_file():
            return
        async with aiosqlite.connect(str(db_path)) as con:
            con.row_factory = aiosqlite.Row
            con.text_factory = self.helpers.smart_decode

            # gowitness result_id -> the URL it visited, used to attribute child rows back to their page
            result_urls = {}
            answered = set()

            # screenshots
            async with con.execute("SELECT * FROM results") as cur:
                async for row in cur:
                    row = dict(row)
                    raw_url = row["url"]
                    result_urls[row["id"]] = raw_url
                    answered_parent = self._resolve_parent(raw_url)
                    if answered_parent is not None:
                        answered.add(id(answered_parent))
                    final_url = row["final_url"]
                    if row.get("failed") or not row.get("filename"):
                        # gowitness keeps a row for a page it could not shoot (timeout, TLS / network error)
                        self._fail(row.get("failed_reason") or "no screenshot taken", raw_url)
                        continue
                    if not (self.screenshot_path / row["filename"]).is_file():
                        self._fail("screenshot not saved (file name too long?)", raw_url)
                        continue
                    # the file exists (checked above): its real name, so the path in the event opens the picture
                    filename = (self.screenshot_path / row["filename"]).relative_to(self.scan.home)
                    parent_event = self._resolve_parent(raw_url)
                    if parent_event is None:
                        self.warning(f"Could not correlate screenshot to parent event for URL: {raw_url}")
                        continue
                    data = {"path": str(filename), "url": final_url}
                    # the answer the browser got (after redirects) and the page title
                    if row.get("response_code"):
                        data["status_code"] = int(row["response_code"])
                    if row.get("title"):
                        data["title"] = str(row["title"])[:300]
                    await self.emit_event(
                        data,
                        "WEBSCREENSHOT",
                        parent=parent_event,
                        context=f"{{module}} visited {final_url} and saved {{event.type}} to {filename}",
                    )
                    self.screenshot_count += 1

            # a page gowitness has no row for at all: the browser got no answer (DNS / connection error)
            for url, e in self._event_dict.items():
                if id(e) not in answered:
                    self._fail("no answer (DNS / connection error or blocked)", url)

            # network logs -> URLs (one event per unique URL within the batch)
            seen_urls = set()
            network_logs = "SELECT * FROM network_logs" if self.network_urls else "SELECT * FROM network_logs LIMIT 0"
            async with con.execute(network_logs) as cur:
                async for row in cur:
                    row = dict(row)
                    url = row["url"]
                    if not (url and url.startswith("http")) or url in seen_urls:
                        continue
                    seen_urls.add(url)
                    raw_parent_url = result_urls.get(row["result_id"])
                    if raw_parent_url is None:
                        continue
                    parent_event = self._resolve_parent(raw_parent_url)
                    if parent_event is None:
                        self.warning(f"Could not correlate network log to parent event for URL: {raw_parent_url}")
                        continue
                    ip = row["remote_ip"]
                    url_event = self.make_event(
                        url,
                        "URL_UNVERIFIED",
                        parent=parent_event,
                        tags=[f"status-{row['status_code']}", "spider-danger"],
                        context=f"{{module}} visited {{event.type}}: {url}",
                    )
                    if url_event and ip:
                        url_event.resolved_hosts = (sys.intern(ip),)
                    await self.emit_event(url_event)

            # technologies
            async with con.execute("SELECT * FROM technologies") as cur:
                async for row in cur:
                    row = dict(row)
                    raw_parent_url = result_urls.get(row["result_id"])
                    if raw_parent_url is None:
                        continue
                    parent_event = self._resolve_parent(raw_parent_url)
                    if parent_event is None:
                        self.warning(f"Could not correlate technology to parent event for URL: {raw_parent_url}")
                        continue
                    technology = row["value"]
                    parent_url = self.helpers.clean_url(raw_parent_url).geturl()
                    await self.emit_event(
                        {"technology": technology, "url": parent_url, "host": str(parent_event.host)},
                        "TECHNOLOGY",
                        parent=parent_event,
                        context=f"{{module}} visited {parent_url} and found {{event.type}}: {technology}",
                    )

    def _fail(self, reason, url):
        reason = " ".join(str(reason).split())[:200]
        self.failures[reason] = self.failures.get(reason, 0) + 1
        self.verbose(f"No screenshot of {url}: {reason}")

    def construct_command(self, db_path):
        # base executable
        command = [str(self.binary), "scan"]
        # chrome path
        if self.chrome_path is not None:
            command += ["--chrome-path", str(self.chrome_path)]
        # db path
        command += ["--write-db"]
        command += ["--write-db-uri", f"sqlite://{db_path}"]
        # screenshot path
        command += ["--screenshot-path", str(self.screenshot_path)]
        # user agent
        command += ["--chrome-user-agent", f"{self.scan.useragent}"]
        # proxy
        if self.proxy:
            command += ["--chrome-proxy", str(self.proxy)]
        # resolution
        command += ["--chrome-window-x", str(self.resolution_x)]
        command += ["--chrome-window-y", str(self.resolution_y)]
        # threads
        command += ["--threads", str(self.threads)]
        # timeout
        command += ["--timeout", str(self.timeout)]
        # why a page failed (timeouts, TLS / DNS errors) goes to the scan's debug log
        command += ["--log-scan-errors"]
        # input
        command += ["file", "-f", "-"]
        return command

    async def report(self):
        if self.failures:
            reasons = "; ".join(f"{n} × {r}" for r, n in sorted(self.failures.items(), key=lambda x: -x[1])[:5])
            self.warning(f"{sum(self.failures.values()):,} pages were not shot: {reasons}")
        if self.screenshot_count:
            self.success(f"{self.screenshot_count:,} web screenshots captured. Saved to: {self.screenshot_path}")
        else:
            self.info("No web screenshots captured")
