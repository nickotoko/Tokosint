from types import SimpleNamespace

from bbot.scanner.stats import ModuleStat, classify_response


def resp(status, text=""):
    return SimpleNamespace(status_code=status, text=text)


def test_classify_response():
    assert classify_response(resp(200), True) == "ok"
    assert classify_response(None, False) == "unavailable"
    assert classify_response(resp(429), False) == "rate_limit"
    assert classify_response(resp(402), False) == "quota"
    assert classify_response(resp(429, '{"error": "Monthly quota exceeded"}'), False) == "quota"
    assert classify_response(resp(403, "Insufficient credits"), False) == "quota"
    assert classify_response(resp(401), False) == "auth"
    assert classify_response(resp(403, "Forbidden"), False) == "auth"
    assert classify_response(resp(503), False) == "server_error"
    assert classify_response(resp(404), False) == "error"


def test_module_stat_requests_hide_keys():
    module = SimpleNamespace(_api_keys=["secretkey123"])
    stat = ModuleStat(module)
    stat.record_request(resp(200), True)
    stat.record_request(resp(429, "slow down, key secretkey123"), False)
    stat.record_request(None, False)
    d = stat.as_dict()
    assert d["requests"] == 3
    assert d["outcomes"] == {"ok": 1, "rate_limit": 1, "unavailable": 1}
    assert "secretkey123" not in d["errors"]["rate_limit"] and "***" in d["errors"]["rate_limit"]
    assert d["errors"]["unavailable"].startswith("no response")
