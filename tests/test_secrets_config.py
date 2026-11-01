from blacktool.secrets import scan_secrets
from blacktool.config_audit import audit_config

def test_secret_value_is_redacted(tmp_path):
    f=tmp_path/"settings.py"; secret="ghp_"+"A"*35
    f.write_text('api_key = "'+secret+'"\n',encoding="utf-8")
    results=scan_secrets(tmp_path)
    assert results and secret not in str(results)
    assert results[0]["rule_id"] in {"SEC003","SEC005","SEC006"}

def test_config_detects_privileged(tmp_path):
    (tmp_path/"compose.yaml").write_text("services:\n  app:\n    privileged: true\n")
    assert any(x["rule_id"]=="CFG001" for x in audit_config(tmp_path))

def test_config_ignores_comments(tmp_path):
    (tmp_path/"compose.yaml").write_text("# privileged: true\n")
    assert audit_config(tmp_path)==[]
