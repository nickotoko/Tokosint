"""Source API keys in config/secrets.yml: list (masked only), add/change, delete.

Which fields are secret comes from BBoT module metadata (`options_sensitive`), not a hardcoded list.
Key values are never returned: only set / not set and the last 4 characters of a long key.
The file is written with mode 600 and its header comments are kept (same as `bin/module key`).
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


def _load(known_modules=()):
    """(header comments, data). The header always ends with a newline: BBoT's own commented secrets template has none
    at the end, and without it the "modules:" line written after the header became part of the last comment, pushing
    the first saved module to the top level. Module blocks found at the top level are moved back under "modules:"."""
    if not SECRETS.exists():
        return "", {}
    text = SECRETS.read_text()
    header = "".join(line for line in text.splitlines(keepends=True) if line.startswith("#"))
    if header and not header.endswith("\n"):
        header += "\n"
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise SecretError("config/secrets.yml is not a YAML mapping: fix or delete it", 500)
    return header, repair(data, known_modules)


def repair(data, known_modules):
    """Moves module blocks written at the top level back under "modules:" (returns the data)."""
    misplaced = [k for k in list(data) if k != "modules" and k in known_modules and isinstance(data[k], dict)]
    if misplaced:
        modules = data.get("modules") or {}
        for k in misplaced:
            modules.setdefault(k, {}).update(data.pop(k))
        data["modules"] = modules
    return data


def _save(header, data):
    tmp = SECRETS.with_suffix(".yml.tmp")
    with open(tmp, "w") as fh:
        fh.write(header + yaml.safe_dump(data, sort_keys=False, allow_unicode=True))
    os.chmod(tmp, 0o600)
    tmp.replace(SECRETS)


def _mask(value):
    if isinstance(value, list):
        return f"{len(value)} key(s)" if value else ""
    value = str(value or "")
    if not value:
        return ""
    return "••••" + value[-4:] if len(value) >= 12 else "••••"


def sensitive_fields(preloaded):
    """{module: {field: {desc, mandatory}}} for active scan modules with secret options."""
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
    _, data = _load(preloaded)
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
        raise SecretError(f"module {module!r} has no secret options (or is not active)")
    if field not in fields:
        raise SecretError(f"module {module} has no secret option {field!r}")


def set_secret(preloaded, module, field, value):
    _check(preloaded, module, field)
    value = str(value or "").strip()
    if not value:
        raise SecretError("empty value: use Delete to remove a key")
    if len(value) > MAX_LEN or any(c in value for c in "\r\n\0"):
        raise SecretError("invalid key value")
    with _lock:
        header, data = _load(preloaded)
        modules = data.get("modules") or {}
        data["modules"] = modules
        modules.setdefault(module, {})[field] = value
        _save(header, data)


def delete_secret(preloaded, module, field):
    _check(preloaded, module, field)
    with _lock:
        header, data = _load(preloaded)
        modules = data.get("modules") or {}
        current = modules.get(module) or {}
        if field not in current:
            raise SecretError("key is not set", 404)
        del current[field]
        if not current:
            modules.pop(module, None)
        _save(header, data)
