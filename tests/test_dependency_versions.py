from blacktool.dependencies import audit_dependencies

def test_pinned_versions_are_identified(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\nrequests>=2.0\n")
    inventory, _ = audit_dependencies(tmp_path)
    assert next(item for item in inventory if item["name"] == "flask")["version"] == "3.0.0"
    assert next(item for item in inventory if item["name"] == "requests")["version"] is None

def test_npm_lockfile_version_is_exact(tmp_path):
    lock = {"lockfileVersion": 3, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.20"}}}
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    inventory, _ = audit_dependencies(tmp_path)
    assert any(item["name"] == "lodash" and item["version"] == "4.17.20" for item in inventory)
