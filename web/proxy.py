"""Proxy for scans: BBoT's `web.http_proxy` (and `web.http_proxy_exclude`) in config/secrets.yml.

secrets.yml is part of the project config (BBOT_CONFIG_DIR), so the proxy applies to every scan - started from the UI
or with bin/osint - and to everything BBoT sends over HTTP: source APIs, the http module, gowitness (its browser gets
--chrome-proxy). It lives in secrets.yml, not bbot.yml, because a proxy URL may carry a login and password: the file is
mode 600 and the UI only gets a masked form (user and password hidden).
"""

import ipaddress
import re
import subprocess
from urllib.parse import urlsplit

import apikeys

SCHEMES = ("http", "https", "socks5", "socks5h")
TEST_URL = "https://example.com/"
_HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$", re.I)


class ProxyError(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.code = code


def parse(url):
    """Checks a proxy URL: scheme://[user[:password]@]host:port. Returns it stripped; raises ProxyError."""
    url = str(url or "").strip()
    if not url or len(url) > 2048 or any(c in url for c in "\r\n\0 "):
        raise ProxyError("proxy: scheme://[user:password@]host:port, e.g. http://127.0.0.1:8080")
    try:
        p = urlsplit(url)
        port = p.port
    except ValueError as e:
        raise ProxyError(f"proxy: {e}") from e
    if p.scheme.lower() not in SCHEMES:
        raise ProxyError(f"proxy scheme: one of {', '.join(SCHEMES)}")
    host = p.hostname or ""
    if not host or not (_is_ip(host) or _HOST_RE.match(host)):
        raise ProxyError("proxy: no valid host")
    if not port:
        raise ProxyError("proxy: the port is required")
    if p.path not in ("", "/") or p.query or p.fragment:
        raise ProxyError("proxy: only scheme://[user:password@]host:port")
    return url


def parse_exclude(items):
    """Hosts / CIDRs that go around the proxy (NO_PROXY)."""
    if isinstance(items, str):
        items = re.split(r"[\s,]+", items)
    out = []
    for x in items or []:
        x = str(x).strip()
        if not x:
            continue
        try:
            ipaddress.ip_network(x, strict=False)
        except ValueError:
            if not _HOST_RE.match(x.lstrip(".*")):
                raise ProxyError(f"proxy exclude: not a host or CIDR: {x}") from None
        out.append(x)
    return out[:200]


def mask(url):
    """scheme://user:•••@host:port - the password never leaves the server; the user name is cut to its first letter."""
    if not url:
        return ""
    p = urlsplit(url)
    cred = ""
    if p.username:
        cred = f"{p.username[:1]}•••" + (":•••" if p.password else "") + "@"
    host = f"[{p.hostname}]" if p.hostname and ":" in p.hostname else (p.hostname or "")
    return f"{p.scheme}://{cred}{host}:{p.port}"


def _is_ip(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _web(data):
    web = data.get("web")
    return web if isinstance(web, dict) else {}


def view():
    _, data = apikeys._load()
    web = _web(data)
    url = web.get("http_proxy") or ""
    return {"set": bool(url), "masked": mask(url), "exclude": list(web.get("http_proxy_exclude") or [])}


def save(payload):
    """payload: {url?, exclude?} - url empty/absent keeps the current proxy (the form never gets it back)."""
    exclude = parse_exclude(payload.get("exclude"))
    url = str(payload.get("url") or "").strip()
    with apikeys._lock:
        header, data = apikeys._load()
        web = _web(data)
        if url:
            web["http_proxy"] = parse(url)
        elif not web.get("http_proxy"):
            raise ProxyError("enter the proxy URL")
        if exclude:
            web["http_proxy_exclude"] = exclude
        else:
            web.pop("http_proxy_exclude", None)
        data["web"] = web
        apikeys._save(header, data)
    return view()


def delete():
    with apikeys._lock:
        header, data = apikeys._load()
        web = _web(data)
        web.pop("http_proxy", None)
        web.pop("http_proxy_exclude", None)
        if web:
            data["web"] = web
        else:
            data.pop("web", None)
        apikeys._save(header, data)
    return view()


def test(payload=None, run=subprocess.run):
    """Fetches TEST_URL through the proxy (the given URL or the saved one) with curl, which speaks HTTP(S) and
    SOCKS proxies. Returns {ok, detail}; the proxy URL is never echoed back."""
    url = str((payload or {}).get("url") or "").strip()
    if url:
        url = parse(url)
    else:
        _, data = apikeys._load()
        url = _web(data).get("http_proxy") or ""
        if not url:
            raise ProxyError("no proxy set")
    try:
        r = run(["curl", "-sS", "-o", "/dev/null", "--max-time", "20", "-x", url,
                 "-w", "%{http_code} %{time_total}", TEST_URL],
                capture_output=True, text=True, timeout=30)  # fmt: skip
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"ok": False, "detail": type(e).__name__}
    out = (r.stdout or "").split()
    code = out[0] if out else "000"
    if r.returncode == 0 and code != "000":
        took = f" in {float(out[1]):.1f} s" if len(out) > 1 else ""
        return {"ok": True, "detail": f"{TEST_URL} answered HTTP {code} through the proxy{took}"}
    err = " ".join((r.stderr or "").split())[:200].replace(url, "<proxy>")
    return {"ok": False, "detail": err or f"curl exit code {r.returncode}"}
