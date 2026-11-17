"""Discovery, parsing and redaction: the auditor's own attack surface."""

from __future__ import annotations

import os

import pytest

from agent_security_auditor.core.discovery import DiscoveryError, DiscoveryLimits, discover
from agent_security_auditor.core.parsing import parse_json, parse_python, parse_yaml
from agent_security_auditor.core.redaction import find_secrets, redact
from conftest import FIXTURES, secret_value


def test_symlinks_are_never_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("X = 1\n")
    target = tmp_path / "target"
    target.mkdir()
    (target / "ok.py").write_text("Y = 2\n")
    os.symlink(outside / "secret.py", target / "link.py")
    os.symlink(outside, target / "linkdir")
    res = discover(target)
    assert [f.rel for f in res.files] == ["ok.py"]
    reasons = {s.rel: s.reason for s in res.skipped}
    assert reasons["link.py"] == "symlink not followed"
    assert reasons["linkdir"] == "symlink not followed"


def test_root_symlink_rejected(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    os.symlink(real, tmp_path / "alias")
    with pytest.raises(DiscoveryError):
        discover(tmp_path / "alias")


def test_limits_and_binary_and_vendored(tmp_path):
    (tmp_path / "big.py").write_text("x" * 5000)
    (tmp_path / "bin.json").write_bytes(b"{\x00\x01}")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text("fetch('https://a.invalid')")
    for i in range(5):
        (tmp_path / f"f{i}.py").write_text("pass\n")
    res = discover(tmp_path, DiscoveryLimits(max_file_bytes=1000, max_files=3))
    reasons = {s.rel: s.reason for s in res.skipped}
    assert "too large" in reasons["big.py"]
    assert reasons["bin.json"] == "binary content"
    assert "vendored" in reasons["node_modules"]
    assert res.truncated and len(res.files) == 3


def test_missing_target():
    with pytest.raises(DiscoveryError):
        discover("/definitely/not/here")


def test_yaml_safe_loader_rejects_python_tags_and_alias_bombs():
    assert not parse_yaml((FIXTURES / "malformed" / "python_tag.yaml").read_text()).ok
    res = parse_yaml((FIXTURES / "malformed" / "alias_bomb.yaml").read_text())
    assert not res.ok and "alias" in res.error


def test_json_depth_limit_and_jsonc():
    assert not parse_json((FIXTURES / "malformed" / "deep.json").read_text()).ok
    assert parse_json('{"a": 1, // comment\n "b": "x//y" /* block */}').value == {"a": 1, "b": "x//y"}


def test_python_is_parsed_never_executed(tmp_path):
    marker = tmp_path / "executed.txt"
    code = f"open({str(marker)!r}, 'w').write('pwned')\n"
    assert parse_python(code).ok
    assert not marker.exists()
    assert not parse_python((FIXTURES / "malformed" / "syntax_error.py").read_text()).ok
    parse_python((FIXTURES / "malformed" / "deep_expr.py").read_text())  # may or may not parse; must not crash


@pytest.mark.parametrize("kind", ["openai", "aws", "github"])
def test_secret_detection_and_redaction(kind):
    value = secret_value(kind)
    text = f'API = "{value}"\n'
    assert find_secrets(text)
    red = redact(text)
    assert value not in red and "REDACTED" in red


def test_placeholders_are_not_secrets():
    for v in ('api_key = "your-api-key-here"', 'password = "changeme123"', 'token = "${TOKEN}"',
              'AWS = "AKIAIOSFODNN7EXAMPLE"', 'secret = "aaaaaaaaaaaa"'):
        assert not find_secrets(v), v


def test_redaction_masks_pii_cards_and_bearer():
    out = redact("mail john.doe@corp.example card 4111 1111 1111 1111 Authorization: Bearer abcdefghijklmnop")
    assert "john.doe" not in out and "j***@corp.example" in out
    assert "4111 1111 1111 1111" not in out and "…1111" in out
    assert "abcdefghijklmnop" not in out
    assert len(redact("x" * 1000)) <= 220
