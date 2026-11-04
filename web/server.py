#!/usr/bin/env python3
"""Бэкенд веб-интерфейса тулкита (стандартная библиотека, без зависимостей).

Маршруты:
  GET /                     index.html
  GET /api/sources          метаданные источников (модули BBoT + квоты)
  GET /api/scans            список сканов в scans/ (имя, число событий, дата)
  GET /api/scan/<name>      активы скана, сгруппированные по (тип, данные) с набором источников
  GET /api/report/<name>    отчёт: сколько и каких данных нашёл каждый источник
  GET /api/jobs             сканы, запущенные из интерфейса (статус, хвост лога)
  POST /api/scans/start     запустить скан: {"targets": [...], "name": "...", "modules": [...]}
  POST /api/jobs/<name>/stop  остановить скан (SIGINT — BBoT дописывает вывод)
  GET /api/keys             API-ключи источников: задан ли (маска), описание поля
  POST /api/keys/set        {"module", "field", "value"} — добавить/изменить ключ в config/secrets.yml
  POST /api/keys/delete     {"module", "field"} — удалить ключ

Запускается через bin/web. Читает scans/ только по запросу из своего же интерфейса на 127.0.0.1.
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
        """POST только со своей страницы: Host — локальный адрес сервера (против DNS rebinding),
        Origin — тот же (против запросов с чужих сайтов), тело — JSON (не «простой» CORS-запрос)."""
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
                raise scans.ScanError("ожидается JSON-объект")
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
            return self._send_json({"error": "некорректный JSON"}, 400)
        except Exception as e:  # noqa: BLE001
            return self._send_json({"error": str(e)}, 500)
        self._send_json({"error": "not found"}, 404)

    def log_message(self, fmt, *args):
        sys.stderr.write("  " + (fmt % args) + "\n")


def health_loop():
    """Фоновый хелчек: при старте — если health.json устарел (>24ч), и далее раз в сутки."""
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
    print(f"Открой http://127.0.0.1:{port}/  (Ctrl+C — остановить)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nостановлено")


if __name__ == "__main__":
    main()
