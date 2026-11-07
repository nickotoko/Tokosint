"""Source quotas: what a scan spent and what is left.

Two sources of truth, shown side by side in the scan report:

1. Our own counter. BBoT counts every API request of every module (each retry too) and its outcome
   (ok / rate_limit / quota / auth / unavailable / server_error / error) and writes them to
   scans/<scan>/module_stats.json at the end of the scan.
2. The source's own account, where it has an endpoint for that (PROBES below). These endpoints do not spend
   the quota themselves. The web server snapshots them right before a scan it starts (quota_before.json) and
   right after it (quota_after.json), so "spent" is the real difference, not an estimate.

For sources without an account endpoint the report shows the requests the scan made against the documented
free limit in quotas.json, plus an estimate of what is left in the current window (requests of all scans
since the window started).

Only numbers are kept: account endpoints also return the owner's name and email, which never leave this module.
"""

import json
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

WEB_DIR = Path(__file__).resolve().parent
ROOT = WEB_DIR.parent
SECRETS = ROOT / "config" / "secrets.yml"
SCANS_DIR = ROOT / "scans"
LIMITS = WEB_DIR / "quota_limits.json"
TIMEOUT = 15
UA = "tokosint"
_cache = {"at": 0, "data": {}}
_lock = threading.Lock()
CACHE_TTL = 60


def _get(url, headers=None, method="GET"):
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})}, method=method,
                                 data=b"" if method == "POST" else None)  # fmt: skip
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode("utf-8", "replace") or "{}")


def _counter(name, remaining, limit, period, used=None):
    """One quota counter: {name, remaining, limit, used, period}."""
    if remaining is None and used is not None and limit is not None:
        remaining = limit - used
    if used is None and remaining is not None and limit is not None:
        used = limit - remaining
    return {"name": name, "remaining": remaining, "limit": limit, "used": used, "period": period}


def _shodan(key):
    d = _get(f"https://api.shodan.io/api-info?key={key}")
    lim = d.get("usage_limits") or {}
    return [_counter("query credits", d.get("query_credits"), lim.get("query_credits"), "month"),
            _counter("scan credits", d.get("scan_credits"), lim.get("scan_credits"), "month")]  # fmt: skip


def _virustotal(key):
    d = (_get(f"https://www.virustotal.com/api/v3/users/{key}/overall_quotas", {"x-apikey": key}).get("data") or {})
    out = []
    for field, period in (("api_requests_daily", "day"), ("api_requests_monthly", "month"), ("api_requests_hourly", "hour")):
        u = (d.get(field) or {}).get("user") or {}
        if u:
            out.append(_counter(f"requests / {period}", None, u.get("allowed"), period, u.get("used")))
    return out


def _hunterio(key):
    d = (_get(f"https://api.hunter.io/v2/account?api_key={key}").get("data") or {})
    s = (d.get("requests") or {}).get("searches") or {}
    return [_counter("searches", s.get("remaining"), s.get("available"), "month", s.get("used"))]


def _fullhunt(key):
    c = _get("https://fullhunt.io/api/v1/auth/status", {"X-API-KEY": key}).get("user_credits") or {}
    return [_counter("credits", c.get("remaining_credits"), c.get("total_credits_per_month"), "month",
                     c.get("credits_usage"))]  # fmt: skip


def _fofa(key):
    d = _get(f"https://fofa.info/api/v1/info/my?key={key}")
    if d.get("error"):
        raise ValueError(str(d.get("errmsg") or "FOFA refused the key")[:120])
    return [_counter("API queries", d.get("remain_api_query"), None, "month"),
            _counter("API data rows", d.get("remain_api_data"), None, "month")]  # fmt: skip


def _postman(key):
    ops = _get("https://api.getpostman.com/me", {"X-API-Key": key}).get("operations") or []
    for op in ops:
        if op.get("name") == "api_usage":
            return [_counter("API calls", None, op.get("limit"), "month", op.get("usage"))]
    return []


def _detectzestack(key):
    # /stats also returns the account name and its top analyzed domains: only the counters are kept
    d = _get("https://detectzestack.com/stats", {"X-API-Key": key})
    return [_counter("requests", d.get("remaining"), d.get("limit"), "month", d.get("used"))]


def _github(_key):
    core = (_get("https://api.github.com/rate_limit").get("resources") or {}).get("core") or {}
    return [_counter("requests / hour (this IP)", core.get("remaining"), core.get("limit"), "hour", core.get("used"))]


# account -> (probe, key module or None, modules it serves). Shodan modules share one key and account.
PROBES = {
    "shodan": (_shodan, "shodan_dns", ["shodan_dns", "shodan_idb"]),
    "virustotal": (_virustotal, "virustotal", ["virustotal"]),
    "hunterio": (_hunterio, "hunterio", ["hunterio"]),
    "fullhunt": (_fullhunt, "fullhunt", ["fullhunt"]),
    "fofa": (_fofa, "fofa", ["fofa"]),
    "postman": (_postman, "postman", ["postman"]),
    "detectzestack": (_detectzestack, "detectzestack", ["detectzestack"]),
    "github": (_github, None, ["github_org", "github_codesearch", "github_workflows"]),
}
MODULE_ACCOUNT = {m: acc for acc, (_, _, mods) in PROBES.items() for m in mods}


def _keys():
    try:
        data = yaml.safe_load(SECRETS.read_text()) or {}
    except (OSError, yaml.YAMLError):
        return {}
    out = {}
    for name, conf in (data.get("modules") or {}).items():
        key = (conf or {}).get("api_key") if isinstance(conf, dict) else None
        if isinstance(key, list):
            key = key[0] if key else None
        if key:
            out[name] = str(key)
    return out


def _probe_one(account, keys):
    probe, key_module, _ = PROBES[account]
    key = keys.get(key_module) if key_module else ""
    if key_module and not key:
        return None
    try:
        return {"at": time.time(), "counters": probe(key)}
    except urllib.error.HTTPError as e:
        return {"at": time.time(), "error": f"HTTP {e.code}"}
    except Exception as e:  # noqa: BLE001 - one dead source must not break the others
        msg = str(e)
        if key:
            msg = msg.replace(key, "***")
        return {"at": time.time(), "error": msg[:120]}


def snapshot(modules=None, use_cache=False):
    """{account: {"at", "counters": [...]} | {"at", "error"}} for accounts of the given modules (None - all)."""
    if use_cache and time.time() - _cache["at"] < CACHE_TTL:
        return _cache["data"]
    accounts = sorted({MODULE_ACCOUNT[m] for m in modules if m in MODULE_ACCOUNT} if modules is not None else PROBES)
    keys = _keys()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = dict(zip(accounts, pool.map(lambda a: _probe_one(a, keys), accounts)))
    data = {a: r for a, r in results.items() if r is not None}
    if modules is None:
        with _lock:
            _cache.update(at=time.time(), data=data)
    return data


def save_snapshot(scan_dir, which, modules=None):
    """Writes quota_before.json / quota_after.json into the scan folder (best effort)."""
    try:
        data = snapshot(modules)
        Path(scan_dir).mkdir(parents=True, exist_ok=True)
        (Path(scan_dir) / f"quota_{which}.json").write_text(json.dumps(data, indent=1))
    except Exception:  # noqa: BLE001
        pass


# ---------- reading a scan ----------

def _read_json(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None


def module_stats(scan_dir):
    return _read_json(Path(scan_dir) / "module_stats.json") or {}


def _limits():
    data = _read_json(LIMITS) or {}
    return {k: v for k, v in data.items() if not k.startswith("_") and isinstance(v, dict)}


PERIOD_SECONDS = {"hour": 3600, "day": 86400, "month": 30 * 86400}


def window_requests(module, period, now=None):
    """Requests a module made in all scans of the current window (by scan start time)."""
    now = now or time.time()
    since = now - PERIOD_SECONDS.get(period, 86400)
    total = 0
    if not SCANS_DIR.is_dir():
        return 0
    for d in SCANS_DIR.iterdir():
        stats = d / "module_stats.json"
        if not stats.is_file():
            continue
        try:
            if stats.stat().st_mtime < since:
                continue
        except OSError:
            continue
        total += int(((_read_json(stats) or {}).get(module) or {}).get("requests") or 0)
    return total


def scan_quota(scan_dir, module):
    """Quota view of one source in one scan: our counter, the account before/after, a free-limit estimate."""
    stats = module_stats(scan_dir).get(module) or {}
    out = {
        "requests": stats.get("requests"),
        "outcomes": stats.get("outcomes") or {},
        "errors": stats.get("errors") or {},
    }
    account = MODULE_ACCOUNT.get(module)
    if account:
        before = (_read_json(Path(scan_dir) / "quota_before.json") or {}).get(account)
        after = (_read_json(Path(scan_dir) / "quota_after.json") or {}).get(account)
        if after or before:
            out["account"] = account
            out["counters"] = _diff(before, after)
            out["account_error"] = (after or before or {}).get("error")
    limit = _limits().get(module)
    if limit:
        used = window_requests(module, limit.get("period", "day"))
        out["free_limit"] = {"limit": limit.get("limit"), "period": limit.get("period", "day"),
                             "used_in_window": used, "per": limit.get("per", "")}  # fmt: skip
        if isinstance(limit.get("limit"), int):
            out["free_limit"]["remaining_estimate"] = max(0, limit["limit"] - used)
    return out


def _diff(before, after):
    """Counters with "spent" = before.remaining - after.remaining (when both snapshots exist)."""
    b = {c["name"]: c for c in (before or {}).get("counters") or []}
    out = []
    for c in (after or before or {}).get("counters") or []:
        c = dict(c)
        prev = b.get(c["name"])
        if after and prev and isinstance(prev.get("remaining"), (int, float)) and isinstance(c.get("remaining"), (int, float)):
            c["spent"] = prev["remaining"] - c["remaining"]
        c["snapshot"] = "after" if after else "before"
        out.append(c)
    return out
