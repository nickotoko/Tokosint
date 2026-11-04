"""API-ключи источников в config/secrets.yml: список (только маска), добавление/изменение, удаление.

Какие поля секретные — из метаданных модулей BBoT (`options_sensitive`), список не зашит вручную.
Значения ключей наружу не отдаются: только «задан / не задан» и последние 4 символа длинного ключа.
Файл пишется с правами 600, комментарии-шапка сохраняются (как в `bin/module key`).
"""

import os
import threading
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SECRETS = ROOT / "config" / "secrets.yml"
MAX_LEN = 4096
_lock = threading.Lock()


class SecretError(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.code = code


def _load():
    if not SECRETS.exists():
        return "", {}
    text = SECRETS.read_text()
    header = "".join(line for line in text.splitlines(keepends=True) if line.startswith("#"))
    return header, yaml.safe_load(text) or {}


def _save(header, data):
    tmp = SECRETS.with_suffix(".yml.tmp")
    with open(tmp, "w") as fh:
        fh.write(header + yaml.safe_dump(data, sort_keys=False, allow_unicode=True))
    os.chmod(tmp, 0o600)
    tmp.replace(SECRETS)


def _mask(value):
    if isinstance(value, list):
        return f"{len(value)} ключ(а)" if value else ""
    value = str(value or "")
    if not value:
        return ""
    return "••••" + value[-4:] if len(value) >= 12 else "••••"


def sensitive_fields(preloaded):
    """{модуль: {поле: {desc, mandatory}}} для активных scan-модулей с секретными опциями."""
    out = {}
    for name, p in sorted(preloaded.items()):
        if p.get("type") != "scan":
            continue
        fields = p.get("options_sensitive") or []
        if not fields:
            continue
        desc = p.get("options_desc") or {}
        mandatory = set(p.get("options_mandatory") or [])
        out[name] = {f: {"desc": desc.get(f, ""), "mandatory": f in mandatory} for f in fields}
    return out


def list_secrets(preloaded):
    _, data = _load()
    modules = (data.get("modules") or {}) if isinstance(data, dict) else {}
    rows = []
    for module, fields in sensitive_fields(preloaded).items():
        current = modules.get(module) or {}
        for field, meta in fields.items():
            value = current.get(field)
            rows.append(
                {
                    "module": module,
                    "field": field,
                    "desc": meta["desc"],
                    "mandatory": meta["mandatory"],
                    "set": bool(value),
                    "masked": _mask(value),
                }
            )
    return rows


def _check(preloaded, module, field):
    fields = sensitive_fields(preloaded).get(module)
    if fields is None:
        raise SecretError(f"у модуля {module!r} нет секретных опций (или он не активен)")
    if field not in fields:
        raise SecretError(f"у модуля {module} нет секретной опции {field!r}")


def set_secret(preloaded, module, field, value):
    _check(preloaded, module, field)
    value = str(value or "").strip()
    if not value:
        raise SecretError("пустое значение — для удаления используйте «Удалить»")
    if len(value) > MAX_LEN or any(c in value for c in "\r\n\0"):
        raise SecretError("недопустимое значение ключа")
    with _lock:
        header, data = _load()
        data.setdefault("modules", {}).setdefault(module, {})[field] = value
        _save(header, data)


def delete_secret(preloaded, module, field):
    _check(preloaded, module, field)
    with _lock:
        header, data = _load()
        modules = data.get("modules") or {}
        current = modules.get(module) or {}
        if field not in current:
            raise SecretError("ключ не задан", 404)
        del current[field]
        if not current:
            modules.pop(module, None)
        _save(header, data)
