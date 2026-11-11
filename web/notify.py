"""Telegram alerts about new valid findings: one summary message per scan, only when something new was found.

The bot token and the default chat id are stored in the settings table (data/tokosint.db); a company may override the
chat id. A company's `alert_types` limits which finding types are alerted (empty = all types). Baseline scans never
alert. The token is never logged or returned to the UI.
"""

import html
import json
import urllib.error
import urllib.request
from collections import Counter

import store

API = "https://api.telegram.org/bot{token}/sendMessage"
MAX_LINES = 25
MAX_TEXT = 3900  # Telegram limit is 4096 characters


def _mask(token):
    return ("••••" + token[-4:]) if len(token) >= 12 else ("••••" if token else "")


def settings_view():
    token = store.get_setting("telegram_token")
    return {"token_set": bool(token), "token_masked": _mask(token), "chat_id": store.get_setting("telegram_chat_id")}


def save_settings(data):
    if "token" in data:
        token = str(data.get("token") or "").strip()
        if token and (len(token) > 200 or ":" not in token or any(c.isspace() for c in token)):
            raise store.StoreError("invalid bot token (expected <id>:<secret> from @BotFather)")
        store.set_setting("telegram_token", token)
    if "chat_id" in data:
        chat = str(data.get("chat_id") or "").strip()
        if chat and not chat.lstrip("-@").replace("_", "").isalnum():
            raise store.StoreError("invalid chat id")
        store.set_setting("telegram_chat_id", chat)
    return settings_view()


def send(text, chat_id=None):
    """Sends a message; returns (ok, description). Never raises, never logs the token."""
    token = store.get_setting("telegram_token")
    chat = chat_id or store.get_setting("telegram_chat_id")
    if not token or not chat:
        return False, "Telegram is not configured (bot token and chat id)"
    body = json.dumps({"chat_id": chat, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}).encode()
    req = urllib.request.Request(API.format(token=token), data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            j = json.loads(r.read() or b"{}")
        return bool(j.get("ok")), j.get("description", "sent")
    except urllib.error.HTTPError as e:
        try:
            desc = json.loads(e.read() or b"{}").get("description", "")
        except ValueError:
            desc = ""
        return False, f"HTTP {e.code} {desc}".strip()
    except Exception as e:  # noqa: BLE001 - network errors must not break scan post-processing
        return False, type(e).__name__


RISK_MARK = {"critical": "🟪", "high": "🟥", "medium": "🟧"}
RISK_RANK = {"critical": 0, "high": 1, "medium": 2}


def format_summary(company, scan, findings, base_url=""):
    by_type = Counter(f["type"] for f in findings)
    by_risk = Counter(f.get("risk") for f in findings if f.get("risk"))
    head = f"<b>Tokosint · {html.escape(company['name'])}</b>\n"
    head += f"{len(findings)} new valid finding(s) in scan <code>{html.escape(scan)}</code>\n"
    if by_risk:
        head += "⚠ " + " · ".join(f"{RISK_MARK[r]} {r}: {by_risk[r]}" for r in RISK_RANK if by_risk.get(r)) + "\n"
    head += " · ".join(f"{html.escape(t)}: {n}" for t, n in by_type.most_common()) + "\n\n"
    lines = []
    # the risky ones first: they are what the alert is for
    ordered = sorted(findings, key=lambda f: RISK_RANK.get(f.get("risk"), 9))
    for f in ordered[:MAX_LINES]:
        mark = " (third party)" if "third-party" in (f.get("tags") or []) else ""
        risk = f.get("risk")
        lead = f"{RISK_MARK[risk]} " if risk in RISK_MARK else "• "
        why = f" — {html.escape(f['risk_reasons'][0])}" if risk and f.get("risk_reasons") else ""
        lines.append(f"{lead}<code>{html.escape(f['type'])}</code> {html.escape(str(f['data'])[:200])}{mark}{why}")
    text = head + "\n".join(lines)
    if len(findings) > MAX_LINES:
        text += f"\n… and {len(findings) - MAX_LINES} more"
    if base_url:
        text += f"\n\nTimeline: {html.escape(base_url)}"
    return text[:MAX_TEXT]


def alert_new_findings(company, scan, result, base_url=""):
    """Called after a company scan is ingested. Returns a short status string for the scan record."""
    if result.get("skipped"):
        return ""
    if result.get("baseline"):
        return "baseline: no alert"
    if not company.get("alerts_enabled"):
        return "alerts disabled for the company"
    types = set(company.get("alert_types") or [])
    findings = [f for f in result.get("new", []) if not types or f["type"] in types]
    if not findings:
        return "nothing new to alert"
    ok, desc = send(format_summary(company, scan, findings, base_url), company.get("telegram_chat_id") or None)
    return f"alert sent ({len(findings)})" if ok else f"alert failed: {desc}"
