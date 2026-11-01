from blacktool.code_audit import scan_source


def test_framework_specific_rules_are_detected(tmp_path):
    source = tmp_path / "settings.py"
    source.write_text('ALLOWED_HOSTS = ["*"]\nCSRF_COOKIE_SECURE = False\n', encoding="utf-8")
    findings = scan_source(tmp_path)
    rule_ids = {item["rule_id"] for item in findings}
    assert "DJ001" in rule_ids
    assert "DJ002" in rule_ids


def test_nextjs_raw_html_sink_is_detected(tmp_path):
    source = tmp_path / "page.tsx"
    source.write_text("return <div dangerouslySetInnerHTML={content} />\n", encoding="utf-8")
    findings = scan_source(tmp_path)
    assert any(item["rule_id"] == "NX001" for item in findings)
