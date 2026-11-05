"""Tests for API key storage in config/secrets.yml: `bbot/.venv/bin/pytest web/test_apikeys.py -q`."""

import pytest
import yaml

import apikeys

# BBoT writes a comment-only secrets template on first run, without a trailing newline
BBOT_TEMPLATE = "# NOTICE: THESE ENTRIES ARE COMMENTED BY DEFAULT\n# modules:\n#   fofa:\n#     api_key: ''"
PRELOADED = {
    "fofa": {"type": "scan", "options_sensitive": ["api_key"], "options_desc": {"api_key": "FOFA key"}},
    "otx": {"type": "scan", "options_sensitive": ["api_key"], "options_mandatory": ["api_key"]},
    "crt": {"type": "scan"},
}


@pytest.fixture
def secrets(tmp_path, monkeypatch):
    path = tmp_path / "secrets.yml"
    monkeypatch.setattr(apikeys, "SECRETS", path)
    return path


def modules_of(path):
    return yaml.safe_load(path.read_text())["modules"]


def test_first_key_on_bbot_template_goes_under_modules(secrets):
    secrets.write_text(BBOT_TEMPLATE)
    apikeys.set_secret(PRELOADED, "fofa", "api_key", "KEY-fofa-123456")
    apikeys.set_secret(PRELOADED, "otx", "api_key", "KEY-otx-1234567")
    data = yaml.safe_load(secrets.read_text())
    assert set(data) == {"modules"}
    assert data["modules"] == {"fofa": {"api_key": "KEY-fofa-123456"}, "otx": {"api_key": "KEY-otx-1234567"}}
    assert secrets.read_text().startswith("# NOTICE")  # the template comments are kept
    assert oct(secrets.stat().st_mode & 0o777) == "0o600"


def test_misplaced_module_block_is_repaired(secrets):
    secrets.write_text("# header\nfofa:\n  api_key: KEY-fofa-123456\nmodules:\n  otx:\n    api_key: KEY-otx-1234567\n")
    rows = {r["module"]: r for r in apikeys.list_secrets(PRELOADED)}
    assert rows["fofa"]["set"] and rows["fofa"]["masked"].endswith("3456")
    apikeys.delete_secret(PRELOADED, "otx", "api_key")
    assert modules_of(secrets) == {"fofa": {"api_key": "KEY-fofa-123456"}}


def test_empty_modules_section(secrets):
    secrets.write_text("modules:\n")
    apikeys.set_secret(PRELOADED, "otx", "api_key", "KEY-otx-1234567")
    assert modules_of(secrets) == {"otx": {"api_key": "KEY-otx-1234567"}}


def test_values_are_validated_and_never_listed(secrets):
    with pytest.raises(apikeys.SecretError):
        apikeys.set_secret(PRELOADED, "crt", "api_key", "x")  # no secret options
    with pytest.raises(apikeys.SecretError):
        apikeys.set_secret(PRELOADED, "otx", "api_key", "a\nb")
    apikeys.set_secret(PRELOADED, "otx", "api_key", "KEY-otx-1234567")
    assert "KEY-otx-1234567" not in str(apikeys.list_secrets(PRELOADED))
