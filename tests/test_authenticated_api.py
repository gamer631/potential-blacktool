import json
from email.message import Message
from unittest.mock import patch

import pytest

from blacktool.authenticated_api import audit_authenticated_endpoints
from blacktool.scope import Scope


class Response:
    status = 200
    headers = Message()
    def __init__(self):
        self.headers["Content-Type"] = "application/json"
        self.headers["Strict-Transport-Security"] = "max-age=31536000"
        self.headers["X-Content-Type-Options"] = "nosniff"
        self.headers["Cache-Control"] = "no-store"
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self, limit): return b'{"ok":true}'


class Opener:
    def __init__(self): self.requests = []
    def open(self, request, timeout):
        self.requests.append((request, timeout))
        return Response()


def test_authenticated_check_uses_bearer_token_without_exposing_it():
    scope = Scope(frozenset({"staging.example"}), max_requests=2)
    opener = Opener()
    with patch.dict("os.environ", {"STAGING_TOKEN":"test-secret"}):
        findings, observations = audit_authenticated_endpoints(
            ["https://staging.example/api/me"], scope, "STAGING_TOKEN", opener
        )
    assert findings == []
    assert observations[0]["status"] == 200
    assert opener.requests[0][0].get_header("Authorization") == "Bearer test-secret"
    assert "test-secret" not in json.dumps([findings, observations])


def test_rejects_out_of_scope_host_before_request():
    scope = Scope(frozenset({"staging.example"}))
    with pytest.raises(ValueError, match="not explicitly allowlisted"):
        audit_authenticated_endpoints(["https://other.example/api"], scope, opener=Opener())


def test_rejects_too_many_endpoints():
    scope = Scope(frozenset({"staging.example"}), max_requests=1)
    with pytest.raises(ValueError, match="request limit"):
        audit_authenticated_endpoints(
            ["https://staging.example/a", "https://staging.example/b"], scope, opener=Opener()
        )
