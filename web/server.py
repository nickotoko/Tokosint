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

Started by bin/web. Listens on 127.0.0.1 and serves scans/ only to its own UI.
"""

import json
import sys
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

WEB_DIR = Path(__file__).resolve().parent
ROOT = WEB_DIR.parent

sys.path.insert(0, str(WEB_DIR))
from _build import build_sources  # noqa: E402
import health  # noqa: E402
import scans  # noqa: E402
import apikeys  # noqa: E402
from bbot.core.modules import MODULE_LOADER  # noqa: E402


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
        route = urlparse(self.path).path
        try:
            if route in ("/", "/index.html"):
                return self._send_file(WEB_DIR / "index.html", "text/html; charset=utf-8")
            if route == "/api/sources":
                return self._send_json(build_sources())
            if route == "/api/health":
                return self._send_json(health.load())
            if route == "/api/scans":
                return self._send_json(scans.list_scans())
            if route == "/api/keys":
                return self._send_json(apikeys.list_secrets(MODULE_LOADER.preloaded()))
            if route == "/api/jobs":
                return self._send_json(scans.list_jobs())
            if route.startswith("/api/report/"):
                producers = {s["name"] for s in build_sources() if s["produced_events"]}
                report = scans.scan_report(unquote(route[len("/api/report/"):]), producers)
                if report is None:
                    return self._send_json({"error": "scan not found"}, 404)
                return self._send_json(report)
            if route.startswith("/api/scan/"):
                path = scans.safe_scan_path(unquote(route[len("/api/scan/"):]))
                if path is None:
                    return self._send_json({"error": "scan not found"}, 404)
                return self._send_json(scans.aggregate_scan(path))
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
            if route == "/api/scans/start":
                known = {s["name"] for s in build_sources()}
                return self._send_json(scans.start_scan(payload, known), 201)
            if route in ("/api/keys/set", "/api/keys/delete"):
                module, field = str(payload.get("module", "")), str(payload.get("field", ""))
                if route.endswith("/set"):
                    apikeys.set_secret(MODULE_LOADER.preloaded(), module, field, payload.get("value"))
                else:
                    apikeys.delete_secret(MODULE_LOADER.preloaded(), module, field)
                return self._send_json(apikeys.list_secrets(MODULE_LOADER.preloaded()))
            if route.startswith("/api/jobs/") and route.endswith("/stop"):
                return self._send_json(scans.stop_scan(unquote(route[len("/api/jobs/"):-len("/stop")])))
        except (scans.ScanError, apikeys.SecretError) as e:
            return self._send_json({"error": str(e)}, e.code)
        except ValueError:
            return self._send_json({"error": "invalid JSON"}, 400)
        except Exception as e:  # noqa: BLE001
            return self._send_json({"error": str(e)}, 500)
        self._send_json({"error": "not found"}, 404)

    def log_message(self, fmt, *args):
        sys.stderr.write("  " + (fmt % args) + "\n")


def health_loop():
    """Background health check: on start if health.json is stale (>24h), then once a day."""
    import time

    while True:
        try:
            if health.is_stale():
                health.run_all()
        except Exception as e:  # noqa: BLE001
            sys.stderr.write(f"  healthcheck error: {e}\n")
        time.sleep(health.TTL)


def main():
    import threading

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8777
    threading.Thread(target=health_loop, daemon=True).start()
    server = ThreadingHTTPServer(("127.0.0.1", port), partial(Handler))
    print(f"Open http://127.0.0.1:{port}/  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
