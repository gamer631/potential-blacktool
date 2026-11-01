from blacktool.osv import query_advisories

def test_osv_ignores_unpinned_packages_without_network():
    findings, checked = query_advisories([
        {"ecosystem": "pypi", "name": "demo", "version": None},
        {"ecosystem": "npm", "name": "other", "version": ""},
    ])
    assert findings == []
    assert checked == 0
