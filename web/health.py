#!/usr/bin/env python3
"""Глубокий хелчек источников: реальным сканом BBoT проверяет, что источник отвечает и отдаёт данные.

Один тестовый скан нейтральных целей (example.com — IANA-домен для примеров, 1.1.1.1 — публичный DNS Cloudflare)
со всеми модулями-источниками. По каждому источнику снимается, что реально произошло:

  ok       источник отработал и отдал данные (produced > 0)
  nodata   источник отработал без ошибки, но данных не вернул (produced == 0)
  down     источник упал (ошибка API/сети) или не стартовал не из-за ключа
  nokey    источнику нужен API-ключ, а в secrets.yml его нет (модуль не стартовал)
  local    у источника нет внешнего эндпоинта (DNS/локальная логика) — реальный запрос не нужен

⚠ Глубокий хелчек делает НАСТОЯЩИЕ запросы и расходует квоту источников (напр., hunter.io — 50 поисков/мес).
Поэтому автозапуск — раз в сутки; для разового запуска вручную: `bin/healthcheck`.

Результат пишется в web/health.json, отдаётся сервером через /api/health.
"""

import asyncio
import json
import shutil
import tempfile
import time
from pathlib import Path

import yaml

WEB_DIR = Path(__file__).resolve().parent
ROOT = WEB_DIR.parent
HEALTH_FILE = WEB_DIR / "health.json"
SECRETS = ROOT / "config" / "secrets.yml"
PROBES = WEB_DIR / "health_probes.json"
TEST_TARGETS = ["example.com", "1.1.1.1"]
TIMEOUT = 420  # жёсткий потолок на весь скан, сек
TTL = 24 * 3600  # автозапуск раз в сутки


def configured_keys():
    """Модули с непустым api_key в secrets.yml (только факт наличия, не значение)."""
    keyed = set()
    if not SECRETS.is_file():
        return keyed
    try:
        data = yaml.safe_load(SECRETS.read_text()) or {}
    except yaml.YAMLError:
        return keyed
    for name, conf in (data.get("modules") or {}).items():
        if isinstance(conf, dict) and str(conf.get("api_key") or "").strip():
            keyed.add(name)
    return keyed


def local_modules():
    """Модули без внешнего эндпоинта (в health_probes.json значение null) — их не тестируем запросом."""
    try:
        probes = json.loads(PROBES.read_text())
    except (OSError, ValueError):
        return set()
    return {k for k, v in probes.items() if k != "_comment" and v is None}


async def _run_scan(sources, timeout):
    from bbot.scanner import Scanner

    tmp = tempfile.mkdtemp(prefix="osint-health-")
    try:
        scan = Scanner(
            *TEST_TARGETS,
            modules=sources,
            name="healthcheck",
            output_dir=tmp,
            config={
                "deps": {"behavior": "disable"},
                "cloudcheck": False,
                "scope": {"report_distance": 1, "search_distance": 1},
            },
        )
        try:
            await asyncio.wait_for(scan.async_start_without_generator(), timeout)
        except asyncio.TimeoutError:
            await scan.stop()
        return scan
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _classify(name, auth_required, scan, keyed, local):
    if name in local:
        return {"status": "local", "detail": "нет внешнего эндпоинта"}
    mod = scan.modules.get(name)
    if mod is None:
        if auth_required and name not in keyed:
            return {"status": "nokey", "detail": "нужен API-ключ, в secrets.yml нет"}
        return {"status": "down", "detail": "модуль не стартовал (setup/ping)"}
    if getattr(mod, "errored", False):
        return {"status": "down", "detail": "ошибка во время запроса (API/сеть/квота)"}
    st = scan.stats.module_stats.get(name)
    produced = getattr(st, "produced_total", 0) if st else 0
    consumed = getattr(st, "consumed_total", 0) if st else 0
    if produced > 0:
        return {"status": "ok", "detail": f"отдал данные: {produced} событий"}
    if consumed > 0:
        return {"status": "nodata", "detail": "отработал, данных не вернул"}
    return {"status": "nodata", "detail": "не получил подходящих событий в тесте"}


def run_all():
    import sys

    sys.path.insert(0, str(WEB_DIR))
    from _build import build_sources

    sources = build_sources()
    names = [s["name"] for s in sources]
    keyed = configured_keys()
    local = local_modules()

    testable = [n for n in names if n not in local]
    scan = asyncio.run(_run_scan(testable, TIMEOUT))

    results = {}
    now = int(time.time())
    for s in sources:
        res = _classify(s["name"], s["auth_required"], scan, keyed, local)
        res["checked_at"] = now
        results[s["name"]] = res

    out = {"checked_at": now, "mode": "deep", "targets": TEST_TARGETS, "sources": results}
    tmp = HEALTH_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(out, ensure_ascii=False, indent=2))
    tmp.replace(HEALTH_FILE)
    return out


def load():
    if HEALTH_FILE.is_file():
        try:
            return json.loads(HEALTH_FILE.read_text())
        except ValueError:
            pass
    return {"checked_at": 0, "sources": {}}


def is_stale():
    return (time.time() - load().get("checked_at", 0)) > TTL


if __name__ == "__main__":
    print("Глубокий хелчек: реальные запросы к источникам (расходует квоту). Это займёт несколько минут…")
    out = run_all()
    counts = {}
    for r in out["sources"].values():
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print("health.json обновлён:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
