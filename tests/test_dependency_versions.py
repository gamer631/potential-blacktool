from blacktool.dependencies import audit_dependencies

def test_pinned_versions_are_identified(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\nrequests>=2.0\n")
    inventory, _ = audit_dependencies(tmp_path)
    assert next(item for item in inventory if item["name"] == "flask")["version"] == "3.0.0"
    assert next(item for item in inventory if item["name"] == "requests")["version"] is None
