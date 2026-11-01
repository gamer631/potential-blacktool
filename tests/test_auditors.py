import json
from blacktool.code_audit import scan_source
from blacktool.api_audit import audit_openapi

def test_source_finds_eval(tmp_path):
    f=tmp_path/"app.py";f.write_text("result = eval(user_input)\n",encoding="utf-8")
    assert any(x["rule_id"]=="PY001" for x in scan_source(tmp_path))

def test_openapi_flags_disabled_security(tmp_path):
    f=tmp_path/"openapi.json"
    f.write_text(json.dumps({"openapi":"3.0.0","paths":{"/private":{"get":{"security":[]}}}}))
    assert any(x["title"]=="Operation explicitly disables security" for x in audit_openapi(f))
