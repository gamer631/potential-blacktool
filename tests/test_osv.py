from blacktool.osv import query_advisories

def test_osv_ignores_unpinned_packages_without_network():
    findings, checked = query_advisories([
        {"ecosystem": "pypi", "name": "demo", "version": None},
        {"ecosystem": "npm", "name": "other", "version": ""},
    ])
    assert findings == []
    assert checked == 0

import json
from unittest.mock import patch
from blacktool.osv import query_advisories

def test_osv_maps_exact_version_response():
    payload = {"results": [{"vulns": [{"id": "GHSA-demo", "summary": "Example advisory", "references": [{"url": "https://example.invalid/advisory"}]}]}]}
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, limit): return json.dumps(payload).encode()
    with patch("urllib.request.urlopen", return_value=Response()):
        findings, checked = query_advisories([{"ecosystem": "pypi", "name": "demo", "version": "1.2.3"}])
    assert checked == 1
    assert findings[0]["rule_id"] == "OSV-GHSA-demo"
    assert findings[0]["version"] == "1.2.3"
