from bbot.modules.base import BaseModule
from bbot.core.config.models import BaseModuleConfig, Field


class detectzestack(BaseModule):
    """
    Query DetectZeStack (https://detectzestack.com) for the technology stack of in-scope websites.

    DetectZeStack fetches the site on its side (HTTP, TLS, DNS and headers, Wappalyzer-based fingerprints, 7,300+
    technologies), so for the scan it is a passive source: the target is not contacted by us. Results are cached by
    DetectZeStack for 24 hours; a cached answer (X-Cache: HIT) does not consume the monthly quota.

    The free plan has 100 requests a month, so lookups are limited per scan (`max_lookups`, only fresh scans count)
    and stop for the rest of the scan once DetectZeStack answers 429 (monthly quota used up). Only resolving in-scope
    names are sent, up to 10 per batch request (each URL is one request of the quota).

    Without a key the module uses the public /demo endpoint (20 lookups an hour per IP, one URL per request).
    """

    watched_events = ["DNS_NAME"]
    produced_events = ["TECHNOLOGY"]
    flags = ["safe", "passive", "web"]
    meta = {
        # DetectZeStack scans the site now (or answers from a cache of at most 24 hours)
        "freshness": "current",
        "description": "Query DetectZeStack for the technology stack of websites (fingerprinted on its side)",
        "created_date": "2026-11-07",
        "author": "@nickotoko",
        # works without a key through /demo (20 lookups an hour); a key gives the monthly plan and batches
        "auth_required": False,
    }

    class Config(BaseModuleConfig):
        api_key: str | list[str] = Field(
            "",
            description="DetectZeStack API key (without it: the /demo endpoint, 20 lookups an hour)",
            sensitive=True,
        )
        max_lookups: int = Field(
            30, description="Max fresh (uncached) lookups per scan: the free plan has 100 a month"
        )
        min_confidence: int = Field(50, description="Ignore technologies detected with a lower confidence (0-100)")
        layers: list = Field(
            [],
            description="Signal layers to keep (http, tls, certificate, wappalyzer, dns); empty - all. "
            "dns hits are mail/DNS providers",
        )

    base_url = "https://detectzestack.com"
    demo_limit = 20
    in_scope_only = True
    _batch_size = 10
    # seeds and early names first: the per-scan budget is small
    _shuffle_incoming_queue = False

    async def setup(self):
        self.max_lookups = int(self.config.get("max_lookups", 30) or 0)
        self.min_confidence = int(self.config.get("min_confidence", 50) or 0)
        self.layers = {str(x).lower() for x in (self.config.get("layers") or [])}
        self.fresh_lookups = 0
        self.quota_exhausted = False
        self.demo = not self.config.get("api_key")
        if self.demo:
            self.max_lookups = min(self.max_lookups, self.demo_limit)
            return True, f"No API key: using the /demo endpoint (at most {self.demo_limit} lookups an hour)"
        ready = await self.require_api_key()
        if ready is True or (isinstance(ready, tuple) and ready[0] is True):
            return ready
        # a refused key (a wrong value pasted, an expired account) should not silence the source: fall back to /demo
        reason = ready[1] if isinstance(ready, tuple) else "the key was refused"
        self.warning(
            f"DetectZeStack key does not work ({reason}): falling back to /demo, {self.demo_limit} lookups an hour"
        )
        self.demo = True
        self.max_lookups = min(self.max_lookups, self.demo_limit)
        return True, "API key refused: using the /demo endpoint"

    def prepare_api_request(self, url, kwargs):
        if not self.demo:
            kwargs["headers"]["X-API-Key"] = self.api_key
        return url, kwargs

    async def ping(self):
        # /stats checks the key and does not consume the quota
        r = await self.api_request(f"{self.base_url}/stats")
        if getattr(r, "status_code", 0) != 200:
            raise ValueError(f"DetectZeStack refused the key (HTTP {getattr(r, 'status_code', 0)})")
        stats = r.json()
        self.verbose(f"DetectZeStack plan {stats.get('tier')}: {stats.get('remaining')} of {stats.get('limit')} left")

    async def filter_event(self, event):
        tags = event.tags
        if "unresolved" in tags or any("wildcard" in t for t in tags):
            return False, "name does not resolve (or resolves only by a wildcard)"
        if not ({"a-record", "aaaa-record", "cname-record"} & tags):
            return False, "name has no address: no website to analyze"
        return True

    # one request analyzes up to 10 sites on DetectZeStack's side: it takes far longer than an ordinary API call
    batch_timeout = 180
    demo_timeout = 60
    max_batch_urls = 10

    @property
    def api_retries(self):
        # every request is paid even when the answer is lost (timeout): never send it twice
        return 1

    def reserve(self, wanted):
        """Takes up to `wanted` lookups from the per-scan budget before the request is sent (a request lost to a
        timeout is still charged by DetectZeStack); cached answers are given back afterwards."""
        n = max(0, min(wanted, self.max_lookups - self.fresh_lookups))
        self.fresh_lookups += n
        return n

    async def handle_batch(self, *events):
        events = list(events)
        # BBoT may hand over more events than _batch_size; the API takes at most 10 URLs per request
        while events and not self.quota_exhausted:
            n = self.reserve(min(len(events), 1 if self.demo else self.max_batch_urls))
            if not n:
                self.debug(f"Per-scan budget of {self.max_lookups} lookups used, skipping {len(events)} names")
                return
            chunk, events = events[:n], events[n:]
            if self.demo:
                await self.lookup_demo(chunk[0])
            else:
                await self.lookup_batch(chunk)

    async def lookup_demo(self, event):
        url = self.helpers.add_get_params(f"{self.base_url}/demo", {"url": event.data}).geturl()
        r = await self.api_request(url, retry_on_http_429=False, timeout=self.demo_timeout)
        if not self.check_response(r):
            return
        result = r.json()
        if result.get("cached"):
            self.fresh_lookups -= 1
        await self.emit_result(event, result)

    async def lookup_batch(self, events):
        by_name = {e.data: e for e in events}
        r = await self.api_request(
            f"{self.base_url}/analyze/batch",
            method="POST",
            json={"urls": list(by_name)},
            retry_on_http_429=False,
            timeout=self.batch_timeout,
        )
        if not self.check_response(r):
            return
        try:
            results = r.json().get("results") or []
        except Exception:
            return
        for item in results:
            result = item.get("result") or {}
            name = str(item.get("url") or result.get("domain") or "").lower().rstrip("/").split("://")[-1]
            event = by_name.get(name) or by_name.get(str(result.get("domain") or "").lower())
            if event is None:
                continue
            if item.get("error") or result.get("cached"):
                # failed scans and cached answers are refunded by DetectZeStack
                self.fresh_lookups -= 1
            if item.get("error"):
                self.debug(f"DetectZeStack could not analyze {name}: {item['error']}")
                continue
            await self.emit_result(event, result)

    def check_response(self, r):
        """True for a usable answer; a 429 (quota / demo hourly limit) stops lookups for the rest of the scan."""
        status = getattr(r, "status_code", 0)
        if status == 429:
            self.quota_exhausted = True
            limit = "hourly demo limit" if self.demo else "monthly quota"
            self.warning(f"DetectZeStack {limit} is used up, no more lookups in this scan")
            return False
        if status != 200:
            self.verbose(f"DetectZeStack request failed (HTTP {status})")
            return False
        return True

    async def emit_result(self, event, result):
        meta = result.get("meta") or {}
        depth = " (DNS only: the site did not answer)" if meta.get("scan_depth") == "partial" else ""
        url = result.get("url") or None
        for tech in result.get("technologies") or []:
            name = str(tech.get("name") or "").strip()
            if not name:
                continue
            confidence = tech.get("confidence")
            if isinstance(confidence, (int, float)) and confidence < self.min_confidence:
                continue
            layer = str(tech.get("source") or "").lower()
            if self.layers and layer not in self.layers:
                continue
            version = str(tech.get("version") or "").strip()
            technology = f"{name} {version}" if version else name
            data = {"technology": technology, "host": event.data}
            if url and "://" in str(url):
                data["url"] = url
            categories = ", ".join(tech.get("categories") or [])
            details = ", ".join(x for x in (categories, f"via {layer}" if layer else "", f"confidence {confidence}"
                                              if confidence is not None else "") if x)  # fmt: skip
            await self.emit_event(
                data,
                "TECHNOLOGY",
                parent=event,
                context=f"{{module}} analyzed {event.data} with DetectZeStack and found {{event.type}}: "
                f"{technology} ({details}){depth}",
            )
