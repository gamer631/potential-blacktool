import json
from blacktool.sarif import to_sarif
from blacktool.policy import violations
from blacktool.dependencies import audit_dependencies

def test_sarif_export_shape():
    result=to_sarif({"findings":[{"rule_id":"PY001","severity":"high","title":"eval","detail":"review","file":"app.py","line":4}]})
    assert result["version"]=="2.1.0"
    assert result["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"]==4

def test_policy_threshold():
    report={"findings":[{"severity":"medium"},{"severity":"high"}]}
    assert len(violations(report,"high"))==1

def test_package_json_inventory(tmp_path):
    (tmp_path/"package.json").write_text(json.dumps({"dependencies":{"express":"^4.0.0"}}))
    inventory,findings=audit_dependencies(tmp_path)
    assert inventory[0]["name"]=="express"
    assert not findings
