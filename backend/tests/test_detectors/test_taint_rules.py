from app.core.scanner import CodeScanner
from app.core.taint_rules import load_taint_rules, normalize_taint_language


def test_load_python_taint_rules():
    rules = load_taint_rules("python")
    assert "request.args" in rules.sources
    assert rules.sinks.get("cursor.execute") == "sql_injection"
    assert "ast.literal_eval" in rules.sanitizers


def test_language_alias_and_fallback():
    js_rules = load_taint_rules("js")
    assert "req.body" in js_rules.sources
    assert normalize_taint_language("ts") == "javascript"
    assert normalize_taint_language("unknown-lang") == "python"


def test_javascript_text_taint_scan_detects_sink():
    code = """
const userCmd = req.query.cmd;
child_process.exec(userCmd);
"""
    scanner = CodeScanner(language="javascript")
    result = scanner.scan_source(code, file_path="sample.js")
    vuln_types = {v.vulnerability_type for v in result.vulnerabilities}
    assert "command_injection" in vuln_types


def test_java_text_taint_scan_detects_sink():
    code = """
String cmd = request.getParameter("cmd");
Runtime.getRuntime.exec(cmd);
"""
    scanner = CodeScanner(language="java")
    result = scanner.scan_source(code, file_path="Sample.java")
    vuln_types = {v.vulnerability_type for v in result.vulnerabilities}
    assert "command_injection" in vuln_types
