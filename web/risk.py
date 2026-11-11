"""Risk level of findings: what deserves attention first (an open database, a login form, a VPN portal...).

The rules live in web/risk.json (ports, technologies, FINDING names, URL paths) and can be edited without code.
A finding gets the highest level of the rules it matches. The level is about the target's exposure, so it follows
the finding's status: valid / untagged - as is, historical - one level down (it may be gone), false and third-party
findings (someone else's infrastructure) - none.

annotate() is applied after manual status overrides (web/overrides.py), so an analyst's decision changes the level.
"""

import json
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

RULES_FILE = Path(__file__).resolve().parent / "risk.json"
LEVELS = ("critical", "high", "medium")
RANK = {None: 0, "medium": 1, "high": 2, "critical": 3}
_PORT_RE = re.compile(r":(\d{1,5})$")
# a URL path rule matches a whole path segment start: /admin matches /admin, /admin/, /admin.php - not /administer
_SEGMENT_END = re.compile(r"[/?#.\-_;]|$")


@lru_cache(maxsize=4)
def _load(path=RULES_FILE, mtime=None):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def rules():
    """The rules file, re-read when it changes (editable while bin/web runs)."""
    try:
        mtime = RULES_FILE.stat().st_mtime
    except OSError:
        return {}
    return _load(RULES_FILE, mtime)


def _down(level):
    i = LEVELS.index(level) + 1 if level in LEVELS else len(LEVELS)
    return LEVELS[i] if i < len(LEVELS) else None


def _ports_of(f):
    ports = set(f.get("ports") or [])
    if f.get("type") == "OPEN_TCP_PORT":
        m = _PORT_RE.search(str(f.get("data") or ""))
        if m:
            ports.add(int(m.group(1)))
    return ports


def _text_rules(items, text):
    text = text.lower()
    return [(r["level"], r["label"]) for r in items if r.get("match", "").lower() in text]


def _url_rules(items, url):
    try:
        path = urlparse(url).path.lower() or "/"
    except ValueError:
        return []
    out = []
    for r in items:
        m = r.get("match", "").lower()
        i = path.find(m)
        if m and i >= 0 and _SEGMENT_END.match(path, i + len(m)):
            out.append((r["level"], r["label"]))
    return out


def matches(f, cfg=None):
    """All (level, reason) pairs the finding matches, regardless of its status."""
    cfg = cfg if cfg is not None else rules()
    etype, data = f.get("type"), f.get("data")
    details = f.get("details") or {}
    out = []
    if etype == "OPEN_TCP_PORT":
        for level, ports in (cfg.get("ports") or {}).items():
            for port in _ports_of(f):
                label = ports.get(str(port))
                if label:
                    out.append((level, f"port {port} open: {label}"))
    elif etype == "TECHNOLOGY":
        name = data if isinstance(data, str) else str((data or {}).get("technology", ""))
        out += [(lvl, f"{label} ({name})") for lvl, label in _text_rules(cfg.get("technologies") or [], name)]
    elif etype in ("FINDING", "VULNERABILITY"):
        text = f"{details.get('name', '')} {details.get('description', '')} {data if isinstance(data, str) else ''}"
        out += _text_rules(cfg.get("findings") or [], text)
        sev = str(details.get("severity") or "").upper()
        level = (cfg.get("finding_severity") or {}).get(sev)
        if level:
            out.append((level, f"{etype.lower()} of severity {sev.lower()}"))
    elif etype == "URL":
        out += _url_rules(cfg.get("urls") or [], str(data or ""))
    return out


def assess(f, cfg=None):
    """(level or None, [reasons]) for an aggregated finding, given its status and ownership."""
    found = matches(f, cfg)
    if not found:
        return None, []
    status = f.get("status")
    tags = set(f.get("tags") or [])
    if status == "false" or "third-party" in tags or f.get("third_party"):
        return None, []
    level = max((lvl for lvl, _ in found), key=lambda x: RANK.get(x, 0))
    reasons = []
    for lvl, reason in sorted(found, key=lambda x: -RANK.get(x[0], 0)):
        if reason not in reasons:
            reasons.append(reason)
    if status == "historical":
        level = _down(level)
        reasons.append("historical: may no longer be exposed")
    return level, reasons


def annotate(findings):
    """Adds risk and risk_reasons to aggregated findings (in place); returns findings."""
    cfg = rules()
    for f in findings:
        f["risk"], f["risk_reasons"] = assess(f, cfg)
    return findings


def counts(findings):
    c = {lvl: 0 for lvl in LEVELS}
    for f in findings:
        if f.get("risk") in c:
            c[f["risk"]] += 1
    return c
