import json
import pytest
from blacktool.scope import Scope

def test_exact_host_allowlist(tmp_path):
    p = tmp_path / "scope.json"
    p.write_text(json.dumps({"allowed_hosts": ["example.com"]}))
    scope = Scope.load(p)
    assert scope.validate_url("https://example.com/") == "example.com"
    with pytest.raises(ValueError):
        scope.validate_url("https://sub.example.com/")

def test_reject_http(tmp_path):
    p = tmp_path / "scope.json"
    p.write_text(json.dumps({"allowed_hosts": ["example.com"]}))
    with pytest.raises(ValueError):
        Scope.load(p).validate_url("http://example.com")
