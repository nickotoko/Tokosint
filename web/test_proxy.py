"""Proxy settings (web/proxy.py): `bbot/.venv/bin/pytest web/test_proxy.py -q`."""

import subprocess

import pytest
import yaml

import apikeys
import proxy


@pytest.fixture(autouse=True)
def secrets(tmp_path, monkeypatch):
    f = tmp_path / "secrets.yml"
    f.write_text("# header\nmodules:\n  fofa:\n    api_key: abcdefabcdef1234\n")
    monkeypatch.setattr(apikeys, "SECRETS", f)
    return f


def test_save_masks_and_keeps_other_secrets(secrets):
    v = proxy.save({"url": "socks5h://alice:s3cret@10.0.0.5:1080", "exclude": "intranet.example, 10.0.0.0/8"})
    assert v == {"set": True, "masked": "socks5h://a•••:•••@10.0.0.5:1080", "exclude": ["intranet.example", "10.0.0.0/8"]}
    data = yaml.safe_load(secrets.read_text())
    assert data["web"]["http_proxy"] == "socks5h://alice:s3cret@10.0.0.5:1080"
    assert data["modules"]["fofa"]["api_key"] == "abcdefabcdef1234"
    assert secrets.read_text().startswith("# header")
    assert oct(secrets.stat().st_mode & 0o777) == "0o600"
    # an empty URL keeps the proxy (the form never gets it back), the exclude list can still change
    assert proxy.save({"url": "", "exclude": ""})["masked"] == "socks5h://a•••:•••@10.0.0.5:1080"
    assert "http_proxy_exclude" not in yaml.safe_load(secrets.read_text())["web"]
    v = proxy.delete()
    assert v["set"] is False and "web" not in yaml.safe_load(secrets.read_text())


@pytest.mark.parametrize("bad", ["", "127.0.0.1:8080", "ftp://h:21", "http://host", "http://h:80/path", "http://h:99999",
                                 "http://bad host:80", "http://h:80\nx"])
def test_invalid_urls(bad):
    with pytest.raises(proxy.ProxyError):
        proxy.parse(bad)


def test_test_uses_curl_and_hides_the_url():
    calls = []

    def ok(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="200 0.42", stderr="")

    r = proxy.test({"url": "http://u:p@127.0.0.1:3128"}, run=ok)
    assert r["ok"] and "HTTP 200" in r["detail"] and "u:p" not in r["detail"]
    assert calls[0][calls[0].index("-x") + 1] == "http://u:p@127.0.0.1:3128"

    def bad(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 7, stdout="000 0", stderr="curl: (7) Failed to connect to http://u:p@127.0.0.1:3128")

    r = proxy.test({"url": "http://u:p@127.0.0.1:3128"}, run=bad)
    assert not r["ok"] and "u:p" not in r["detail"] and "<proxy>" in r["detail"]
    with pytest.raises(proxy.ProxyError):
        proxy.test({})  # nothing saved
