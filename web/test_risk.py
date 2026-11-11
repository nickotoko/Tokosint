"""Risk levels of findings (web/risk.py, rules in web/risk.json)."""

import notify
import risk


def f(etype, data, status="valid", tags=(), **kw):
    return {"type": etype, "data": data, "status": status, "tags": list(tags), **kw}


def test_database_port_is_critical():
    level, reasons = risk.assess(f("OPEN_TCP_PORT", "db.target.example:3306"))
    assert level == "critical"
    assert "MySQL" in reasons[0]


def test_remote_access_and_plain_ports():
    assert risk.assess(f("OPEN_TCP_PORT", "1.2.3.4:3389"))[0] == "high"
    assert risk.assess(f("OPEN_TCP_PORT", "mail.target.example:22"))[0] == "medium"
    assert risk.assess(f("OPEN_TCP_PORT", "www.target.example:443")) == (None, [])


def test_technology_substring():
    assert risk.assess(f("TECHNOLOGY", "phpmyadmin"))[0] == "critical"
    assert risk.assess(f("TECHNOLOGY", "oracle-mysql"))[0] == "critical"
    assert risk.assess(f("TECHNOLOGY", "watchguard-sslvpn"))[0] == "high"
    assert risk.assess(f("TECHNOLOGY", "nginx"))[0] is None


def test_findings_by_name_and_severity():
    login = f("FINDING", "https://target.example/", details={"name": "Login page", "severity": "INFO"})
    assert risk.assess(login) == ("high", ["login form"])
    vuln = f("VULNERABILITY", "target.example", details={"name": "CVE-X", "severity": "CRITICAL"})
    assert risk.assess(vuln)[0] == "critical"
    info = f("FINDING", "target.example", details={"name": "Something", "severity": "INFO"})
    assert risk.assess(info)[0] is None


def test_url_path_segments():
    assert risk.assess(f("URL", "https://target.example/bitrix/admin/"))[0] == "high"
    assert risk.assess(f("URL", "https://target.example/admin.php"))[0] == "high"
    assert risk.assess(f("URL", "https://target.example/.git/config"))[0] == "critical"
    # a segment start, not any substring
    assert risk.assess(f("URL", "https://target.example/administer-news/"))[0] is None
    assert risk.assess(f("URL", "https://target.example/author/x"))[0] is None
    assert risk.assess(f("URL", "https://target.example/"))[0] is None


def test_status_and_ownership():
    port = "db.target.example:5432"
    assert risk.assess(f("OPEN_TCP_PORT", port, status=None))[0] == "critical"  # untagged scan
    level, reasons = risk.assess(f("OPEN_TCP_PORT", port, status="historical"))
    assert level == "high" and reasons[-1].startswith("historical")
    assert risk.assess(f("OPEN_TCP_PORT", "1.2.3.4:22", status="historical"))[0] is None  # medium -> none
    assert risk.assess(f("OPEN_TCP_PORT", port, status="false")) == (None, [])
    assert risk.assess(f("OPEN_TCP_PORT", port, tags=["third-party"])) == (None, [])
    # timeline rows carry third_party instead of the tag
    assert risk.assess(f("OPEN_TCP_PORT", port, third_party=True)) == (None, [])


def test_annotate_and_counts():
    items = risk.annotate([f("OPEN_TCP_PORT", "a.target.example:6379"), f("DNS_NAME", "a.target.example")])
    assert items[0]["risk"] == "critical" and items[1]["risk"] is None and items[1]["risk_reasons"] == []
    assert risk.counts(items) == {"critical": 1, "high": 0, "medium": 0}


def test_telegram_summary_puts_risky_first():
    items = risk.annotate([f("DNS_NAME", "a.target.example"), f("OPEN_TCP_PORT", "a.target.example:27017")])
    text = notify.format_summary({"name": "Co"}, "scan1", items)
    assert "critical: 1" in text
    lines = [line for line in text.splitlines() if "target.example" in line]
    assert "27017" in lines[0] and "MongoDB" in lines[0]
