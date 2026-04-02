import ast

from app.core.detectors.exception_handling import ExceptionHandlingDetector
from app.core.detectors.supply_chain import SupplyChainDetector
from app.core.scanner import CodeScanner


def _run_detector(detector, code: str):
    tree = ast.parse(code)
    lines = code.splitlines()
    return detector.detect(tree, "test.py", code, lines)


def test_exception_detector_flags_bare_and_silent_except():
    code = """
def authorize(token):
    try:
        return verify(token)
    except:
        pass
"""
    vulns = _run_detector(ExceptionHandlingDetector(), code)
    assert vulns
    assert any(v.vulnerability_type == "exception_mishandling" for v in vulns)


def test_exception_detector_skips_explicit_safe_handling():
    code = """
def parse_count(value):
    try:
        return int(value)
    except ValueError:
        return None
"""
    vulns = _run_detector(ExceptionHandlingDetector(), code)
    assert vulns == []


def test_supply_chain_manifest_scan_detects_typosquat_and_unpinned(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("reqeusts==2.31.0\nflask\n", encoding="utf-8")

    detector = SupplyChainDetector()
    vulns = detector.scan_manifest_file(str(manifest))

    assert len(vulns) >= 2
    assert all(v.vulnerability_type == "supply_chain_failure" for v in vulns)
    descriptions = [v.description.lower() for v in vulns]
    assert any("suspicious" in d for d in descriptions)
    assert any("unpinned" in d for d in descriptions)


def test_scanner_includes_requirements_manifest_findings(tmp_path):
    (tmp_path / "safe.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("requests\n", encoding="utf-8")

    scanner = CodeScanner(language="python")
    result = scanner.scan_directory(str(tmp_path))

    types = {v.vulnerability_type for v in result.vulnerabilities}
    assert "supply_chain_failure" in types
