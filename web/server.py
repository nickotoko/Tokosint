#!/usr/bin/env python3
"""Tokosint web backend (standard library only, no dependencies).

Routes:
  GET /                     index.html
  GET /api/sources          source metadata (BBoT modules + quotas)
  GET /api/scans            scans in scans/ (name, event count, date)
  GET /api/scan/<name>      scan findings grouped by (type, data) with their sources
  GET /api/report/<name>    report: what and how much each source found
  GET /api/jobs             scans started from the UI (status, log tail)
  POST /api/scans/start     start a scan: {"targets": [...], "name": "...", "modules": [...]}
  POST /api/jobs/<name>/stop  stop a scan (SIGINT - BBoT finishes writing its output)
  GET /api/keys             source API keys: set or not (masked), field description
  POST /api/keys/set        {"module", "field", "value"} - add/change a key in config/secrets.yml
  POST /api/keys/delete     {"module", "field"} - delete a key
  GET /api/companies        companies with their schedules
  POST /api/companies/save  {"id"?, "name", "description", "targets", "alerts_enabled", "alert_types", "telegram_chat_id"}
  POST /api/companies/delete {"id"} - company, schedules, registry and timeline (scan files are kept)
  POST /api/companies/attach {"id", "scans": [...]} - link existing scans and rebuild the timeline (no alerts)
  GET /api/timeline/<id>    timeline of a company (?type=, ?kind=new|baseline)
  POST /api/schedules/save  {"id"?, "company_id", "cron", "modules", "enabled"}
  POST /api/schedules/delete {"id"}
  GET /api/cron?expr=...    validate a cron expression and show the next runs
  GET /api/telegram         Telegram settings (token masked)
  POST /api/telegram/save   {"token"?, "chat_id"?}
  POST /api/telegram/test   {"chat_id"?} - send a test message
  GET /api/proxy            proxy of the scans (web.http_proxy in secrets.yml; masked)
  POST /api/proxy/save      {"url"?, "exclude"?}; POST /api/proxy/delete; POST /api/proxy/test {"url"?}
  GET /api/screenshots      every gowitness screenshot (?scan= one scan with its enrichments)
  GET /api/chain/<name>?type=&data=  every discovery chain of a finding (seed -> ... -> finding, with statuses)
  GET /api/enrich/<name>?modules=a,b  what enriching a finished scan with these sources would send (seeds, scope)
  POST /api/enrich/<name>   {"modules": [...]} - run the sources over the scan's findings (web/enrich.py)
  GET /api/quota            remaining quota of the sources' accounts (cached 60 s; no quota spent)
  POST /api/status/set      {"scan", "type", "data", "status": valid|historical|false|"", "note"?} - manual status
  GET /api/status/log       every manual status change with the computed status and the evidence snapshot

Started by bin/web. Listens on 127.0.0.1 and serves scans/ only to its own UI.
"""

import json
import sys
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

WEB_DIR = Path(__file__).resolve().parent
ROOT = WEB_DIR.parent

sys.path.insert(0, str(WEB_DIR))
from _build import build_chord, build_sources  # noqa: E402
import health  # noqa: E402
import scans  # noqa: E402
import apikeys  # noqa: E402
import companies  # noqa: E402
import cronexpr  # noqa: E402
import notify  # noqa: E402
import store  # noqa: E402
import overrides  # noqa: E402
import enrich  # noqa: E402
import quota  # noqa: E402
import risk  # noqa: E402
import proxy  # noqa: E402
from bbot.core.modules import MODULE_LOADER  # noqa: E402

BBOT_DOCS = ROOT / "bbot" / "docs"
VEGA_FILES = {
    "vega.js": BBOT_DOCS / "javascripts" / "vega@5.js",
    "vega-lite.js": BBOT_DOCS / "javascripts" / "vega-lite@5.js",
    "vega-embed.js": BBOT_DOCS / "javascripts" / "vega-embed@6.js",
    "chord.json": BBOT_DOCS / "data" / "chord_graph" / "vega.json",
}
I18N_FILES = {
    "ru.json": (WEB_DIR / "i18n_ru.json", "application/json; charset=utf-8"),
    "howto_ru.html": (WEB_DIR / "howto_ru.html", "text/html; charset=utf-8"),
}
VEGA_TYPES = {"js": "application/javascript; charset=utf-8", "json": "application/json; charset=utf-8"}


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path, ctype):
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        route, query = parsed.path, {k: v[0] for k, v in parse_qs(parsed.query).items()}
        try:
            if route in ("/", "/index.html"):
                return self._send_file(WEB_DIR / "index.html", "text/html; charset=utf-8")
            if route == "/api/sources":
                return self._send_json(build_sources())
            if route == "/api/chord":
                return self._send_json(build_chord())
            if route.startswith("/i18n/"):
                # interface translations: the dictionary and the Russian text of the "How it works" tab
                name = route[len("/i18n/"):]
                if name not in I18N_FILES:
                    return self._send_json({"error": "not found"}, 404)
                return self._send_file(*I18N_FILES[name])
            if route.startswith("/static/vega/"):
                # BBoT's documentation bundles (vega, vega-embed, vega-lite) and its chord graph spec, served locally
                name = route[len("/static/vega/"):]
                if name not in VEGA_FILES:
                    return self._send_json({"error": "not found"}, 404)
                return self._send_file(VEGA_FILES[name], VEGA_TYPES[name.rsplit(".", 1)[-1]])
            if route.startswith("/api/screenshot/"):
                # /api/screenshot/<scan>/<path inside the scan>: a gowitness image (see scans.screenshot_file)
                rest = unquote(route[len("/api/screenshot/"):])
                scan, _, rel = rest.partition("/")
                f = scans.screenshot_file(scan, rel)
                if f is None:
                    return self._send_json({"error": "not found"}, 404)
                return self._send_file(f, scans.SCREENSHOT_TYPES[f.suffix.lower()])
            if route == "/api/health":
                return self._send_json(health.load())
            if route == "/api/scans":
                owners = store.scan_companies()
                out = scans.list_scans()
                for sc in out:
                    sc["company"] = owners.get(sc["name"], "")
                return self._send_json(out)
            if route == "/api/keys":
                return self._send_json(apikeys.list_secrets(MODULE_LOADER.preloaded()))
            if route == "/api/jobs":
                return self._send_json(scans.list_jobs())
            if route == "/api/companies":
                schedules = store.list_schedules()
                out = store.list_companies()
                for co in out:
                    co["schedules"] = [s for s in schedules if s["company_id"] == co["id"]]
                return self._send_json(out)
            if route.startswith("/api/timeline/"):
                cid = int(route[len("/api/timeline/"):])
                tl = store.timeline(cid, kind=query.get("kind"), type_=query.get("type"))
                risk.annotate(tl["events"])
                return self._send_json(tl)
            if route == "/api/cron":
                try:
                    expr = cronexpr.validate(query.get("expr", ""))
                except cronexpr.CronError as e:
                    return self._send_json({"error": str(e)}, 400)
                runs, t = [], None
                for _ in range(3):
                    t = cronexpr.next_run(expr, t)
                    runs.append(t.strftime("%Y-%m-%d %H:%M"))
                return self._send_json({"cron": expr, "next": runs})
            if route == "/api/quota":
                return self._send_json({"modules": quota.MODULE_ACCOUNT, "accounts": quota.snapshot(use_cache=True)})
            if route == "/api/status/log":
                return self._send_json(store.override_log())
            if route == "/api/telegram":
                return self._send_json(notify.settings_view())
            if route == "/api/proxy":
                return self._send_json(proxy.view())
            if route == "/api/screenshots":
                return self._send_json(scans.list_screenshots(query.get("scan") or None))
            if route.startswith("/api/report/"):
                producers = {s["name"] for s in build_sources() if s["produced_events"]}
                report = scans.scan_report(unquote(route[len("/api/report/"):]), producers)
                if report is None:
                    return self._send_json({"error": "scan not found"}, 404)
                return self._send_json(report)
            if route.startswith("/api/chain/"):
                path = scans.safe_scan_path(unquote(route[len("/api/chain/"):]))
                if path is None:
                    return self._send_json({"error": "scan not found"}, 404)
                return self._send_json(scans.discovery_chains(path, query.get("type", ""), query.get("data", "")))
            if route.startswith("/api/scan/"):
                path = scans.safe_scan_path(unquote(route[len("/api/scan/"):]))
                if path is None:
                    return self._send_json({"error": "scan not found"}, 404)
                name = unquote(route[len("/api/scan/"):])
                # the scan together with its enrichments (new sources run over its findings later)
                return self._send_json(risk.annotate(overrides.apply(name, scans.aggregate_scan(path, include_enrichments=True))))
            if route.startswith("/api/enrich/"):
                name = unquote(route[len("/api/enrich/"):])
                modules = [m for m in str(query.get("modules", "")).split(",") if m]
                try:
                    return self._send_json(enrich.summary(enrich.plan(name, modules, MODULE_LOADER.preloaded())))
                except enrich.EnrichError as e:
                    return self._send_json({"error": str(e)}, e.code)
        except Exception as e:  # noqa: BLE001
            return self._send_json({"error": str(e)}, 500)
        self._send_json({"error": "not found"}, 404)

    def _same_origin(self):
        """POST only from our own page: Host is the server's local address (against DNS rebinding),
        Origin is the same (against requests from other sites), the body is JSON (not a "simple" CORS request)."""
        host = self.headers.get("Host", "")
        port = self.server.server_address[1]
        if host not in (f"127.0.0.1:{port}", f"localhost:{port}"):
            return False
        origin = self.headers.get("Origin")
        if origin is not None and origin != f"http://{host}":
            return False
        return self.headers.get("Content-Type", "").split(";")[0].strip() == "application/json"

    def do_POST(self):
        route = urlparse(self.path).path
        if not self._same_origin():
            return self._send_json({"error": "forbidden"}, 403)
        try:
            length = min(int(self.headers.get("Content-Length") or 0), 64 * 1024)
            payload = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(payload, dict):
                raise scans.ScanError("a JSON object is expected")
            known = {s["name"] for s in build_sources()}
            if route.startswith("/api/enrich/"):
                name = unquote(route[len("/api/enrich/"):])
                modules = payload.get("modules") or []
                if not isinstance(modules, list) or any(m not in known for m in modules):
                    return self._send_json({"error": "unknown source in the module list"}, 400)
                job = enrich.start(name, modules, MODULE_LOADER.preloaded(), known, on_finish=companies.process_scan)
                return self._send_json(job, 201)
            if route == "/api/scans/start":
                if payload.get("company_id"):
                    targets = scans.parse_targets(payload.get("targets")) if payload.get("targets") else None
                    name = str(payload.get("name") or "").strip().lower() or None
                    job = companies.start_company_scan(int(payload["company_id"]), payload.get("modules") or [], known,
                                                       name=name, targets=targets)  # fmt: skip
                    return self._send_json(job, 201)
                return self._send_json(scans.start_scan(payload, known), 201)
            if route == "/api/companies/save":
                cid = int(payload["id"]) if payload.get("id") else None
                return self._send_json(store.save_company(payload, cid, parse_targets=scans.parse_targets))
            if route == "/api/companies/delete":
                store.delete_company(int(payload.get("id") or 0))
                return self._send_json({"ok": True})
            if route == "/api/companies/attach":
                names = [str(n) for n in (payload.get("scans") or [])]
                return self._send_json(companies.attach_scans(int(payload.get("id") or 0), names))
            if route == "/api/schedules/save":
                sid = int(payload["id"]) if payload.get("id") else None
                data = companies.schedule_payload(payload, known)
                return self._send_json(store.save_schedule(data, companies.next_run_ts(data["cron"]), sid))
            if route == "/api/schedules/delete":
                store.delete_schedule(int(payload.get("id") or 0))
                return self._send_json({"ok": True})
            if route == "/api/status/set":
                return self._send_json(overrides.set_status(payload))
            if route == "/api/proxy/save":
                return self._send_json(proxy.save(payload))
            if route == "/api/proxy/delete":
                return self._send_json(proxy.delete())
            if route == "/api/proxy/test":
                res = proxy.test(payload)
                return self._send_json(res, 200 if res["ok"] else 502)
            if route == "/api/telegram/save":
                return self._send_json(notify.save_settings(payload))
            if route == "/api/telegram/test":
                ok, desc = notify.send("<b>Tokosint</b>: test message", payload.get("chat_id") or None)
                return self._send_json({"ok": ok, "detail": desc}, 200 if ok else 502)
            if route in ("/api/keys/set", "/api/keys/delete"):
                module, field = str(payload.get("module", "")), str(payload.get("field", ""))
                if route.endswith("/set"):
                    apikeys.set_secret(MODULE_LOADER.preloaded(), module, field, payload.get("value"))
                else:
                    apikeys.delete_secret(MODULE_LOADER.preloaded(), module, field)
                return self._send_json(apikeys.list_secrets(MODULE_LOADER.preloaded()))
            if route.startswith("/api/jobs/") and route.endswith("/stop"):
                return self._send_json(scans.stop_scan(unquote(route[len("/api/jobs/"):-len("/stop")])))
        except (scans.ScanError, apikeys.SecretError, store.StoreError, proxy.ProxyError) as e:
            return self._send_json({"error": str(e)}, e.code)
        except cronexpr.CronError as e:  # a ValueError: must be caught before "invalid JSON"
            return self._send_json({"error": f"cron: {e}"}, 400)
        except ValueError:
            return self._send_json({"error": "invalid JSON"}, 400)
        except Exception as e:  # noqa: BLE001
            return self._send_json({"error": str(e)}, 500)
        self._send_json({"error": "not found"}, 404)

    def log_message(self, fmt, *args):
        sys.stderr.write("  " + (fmt % args) + "\n")


def health_loop(idle_poll=60):
    """Background health check: on start if health.json is stale (>24h), then once a day.

    Runs in a separate process (health.run_isolated - an in-process BBoT scan kills the server's children on
    timeout, i.e. the user's scan) and only when no scan is running: the check spends the same source quotas and
    rate limits, so running both at once makes the user's scan hit 429s."""
    import time

    while True:
        try:
            if health.is_stale():
                while scans.running_job():
                    time.sleep(idle_poll)
                health.run_isolated(env=scans._child_env())
        except Exception as e:  # noqa: BLE001
            sys.stderr.write(f"  healthcheck error: {e}\n")
        time.sleep(health.TTL)


def main():
    import threading

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8777
    store.init()
    companies.migrate_registries()
    companies.BASE_URL = f"http://127.0.0.1:{port}/#timeline"
    threading.Thread(target=health_loop, daemon=True).start()
    known = lambda: {s["name"] for s in build_sources()}  # noqa: E731
    threading.Thread(target=companies.scheduler_loop, args=(known,), daemon=True).start()
    server = ThreadingHTTPServer(("127.0.0.1", port), partial(Handler))
    print(f"Open http://127.0.0.1:{port}/  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
