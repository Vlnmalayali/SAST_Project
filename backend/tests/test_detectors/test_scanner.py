import os
import tempfile
import pytest
from app.core.scanner import CodeScanner


class TestCodeScanner:
    def test_scan_vulnerable_source(self, vulnerable_python_code):
        scanner = CodeScanner()
        result = scanner.scan_source(vulnerable_python_code)

        assert result.total_files_scanned == 1
        assert result.total_lines_scanned > 0
        assert len(result.vulnerabilities) >= 5  # multiple types
        assert result.overall_risk_score > 0

        vuln_types = {v.vulnerability_type for v in result.vulnerabilities}
        assert "sql_injection" in vuln_types
        assert "command_injection" in vuln_types
        assert "weak_crypto" in vuln_types
        assert "unsafe_eval" in vuln_types

    def test_scan_clean_code(self):
        code = '''
def add(a: int, b: int) -> int:
    return a + b

def greet(name: str) -> str:
    return f"Hello, {name}"
'''
        scanner = CodeScanner()
        result = scanner.scan_source(code)
        assert len(result.vulnerabilities) == 0
        assert result.overall_risk_score == 0.0

    def test_scan_directory(self, tmp_path):
        vuln_file = tmp_path / "vuln.py"
        vuln_file.write_text('import os\ndef run(cmd):\n    os.system(cmd)\n')

        safe_file = tmp_path / "safe.py"
        safe_file.write_text('def add(a, b):\n    return a + b\n')

        scanner = CodeScanner()
        result = scanner.scan_directory(str(tmp_path))

        assert result.total_files_scanned == 2
        assert len(result.vulnerabilities) >= 1

    def test_inline_nosast_suppression_python(self):
        code = """
def run(cmd):
    os.system(cmd)  # nosast
"""
        scanner = CodeScanner()
        result = scanner.scan_source(code, file_path="suppressed.py")
        assert len(result.vulnerabilities) == 0

    def test_inline_nosast_suppression_javascript(self):
        code = """
const userCmd = req.query.cmd;
child_process.exec(userCmd); // nosast
"""
        scanner = CodeScanner(language="javascript")
        result = scanner.scan_source(code, file_path="suppressed.js")
        assert len(result.vulnerabilities) == 0
