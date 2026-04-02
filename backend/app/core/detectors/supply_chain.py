"""Detector for software supply chain failures (OWASP A03:2025)."""

import ast
import re
from pathlib import Path

from app.core.detectors.base import BaseDetector, VulnerabilityFound

SUSPICIOUS_PACKAGES = {
    "colourama",  # typosquat-style example
    "reqeusts",   # typo of requests
    "urllib4",    # typo of urllib3
}

RUNTIME_INSTALL_FUNCS = {"os.system", "subprocess.call", "subprocess.run", "subprocess.Popen"}
RUNTIME_INSTALL_PATTERN = re.compile(r"\b(?:pip|python\s+-m\s+pip)\s+install\b", re.IGNORECASE)

SETUP_EXECUTION_PATTERNS = (
    re.compile(r"os\.system\s*\(", re.IGNORECASE),
    re.compile(r"subprocess\.(?:call|run|Popen)\s*\(", re.IGNORECASE),
    re.compile(r"exec\s*\(\s*open\s*\(", re.IGNORECASE),
)

REQUIREMENTS_FILE_PATTERN = re.compile(r"^requirements(?:[-_.].+)?\.txt$", re.IGNORECASE)
PIN_OPERATOR_PATTERN = re.compile(r"(==|~=|>=|<=|!=|===|>|<|@)")


class SupplyChainDetector(BaseDetector):
    """
    Detect supply-chain risks (OWASP A03:2025) in Python projects.

    - Typosquatted or suspicious package references
    - Runtime package installation
    - setup.py install-time command execution patterns
    - Unpinned dependencies in requirements files
    """

    name = "supply_chain_failure"
    description = "Detects software supply-chain risks"
    default_severity = "high"
    cwe_id = "CWE-1104"

    def detect(
        self, tree: ast.AST, file_path: str, source_code: str, source_lines: list[str]
    ) -> list[VulnerabilityFound]:
        vulnerabilities: list[VulnerabilityFound] = []
        seen: set[tuple[int, str]] = set()
        filename = Path(file_path).name.lower()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    package = alias.name.split(".")[0].lower()
                    if package in SUSPICIOUS_PACKAGES:
                        self._add_unique(
                            vulnerabilities,
                            seen,
                            line=node.lineno,
                            code=self._get_line_source(source_lines, node.lineno),
                            source_lines=source_lines,
                            file_path=file_path,
                            confidence=0.88,
                            severity="high",
                            description=f"Suspicious package import '{package}' may be typosquatted.",
                        )

            if isinstance(node, ast.ImportFrom) and node.module:
                package = node.module.split(".")[0].lower()
                if package in SUSPICIOUS_PACKAGES:
                    self._add_unique(
                        vulnerabilities,
                        seen,
                        line=node.lineno,
                        code=self._get_line_source(source_lines, node.lineno),
                        source_lines=source_lines,
                        file_path=file_path,
                        confidence=0.88,
                        severity="high",
                        description=f"Suspicious package import '{package}' may be typosquatted.",
                    )

            if not isinstance(node, ast.Call):
                continue

            func_name = self._get_call_name(node.func)
            if not func_name:
                continue

            if func_name in RUNTIME_INSTALL_FUNCS and node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                    if RUNTIME_INSTALL_PATTERN.search(first_arg.value):
                        self._add_unique(
                            vulnerabilities,
                            seen,
                            line=node.lineno,
                            code=self._get_line_source(source_lines, node.lineno),
                            source_lines=source_lines,
                            file_path=file_path,
                            confidence=0.82,
                            severity="high",
                            description="Runtime dependency installation detected; this increases supply-chain risk.",
                        )

            if func_name == "exec" and node.args:
                if self._is_exec_open_read(node.args[0]):
                    self._add_unique(
                        vulnerabilities,
                        seen,
                        line=node.lineno,
                        code=self._get_line_source(source_lines, node.lineno),
                        source_lines=source_lines,
                        file_path=file_path,
                        confidence=0.85,
                        severity="critical",
                        description="Dynamic execution of file content detected (exec(open(...))).",
                    )

        if filename == "setup.py":
            for index, line in enumerate(source_lines, start=1):
                for pattern in SETUP_EXECUTION_PATTERNS:
                    if pattern.search(line):
                        self._add_unique(
                            vulnerabilities,
                            seen,
                            line=index,
                            code=line.strip(),
                            source_lines=source_lines,
                            file_path=file_path,
                            confidence=0.84,
                            severity="high",
                            description="setup.py appears to execute system commands during build/install.",
                        )
                        break

        return vulnerabilities

    def scan_manifest_file(self, file_path: str) -> list[VulnerabilityFound]:
        """
        Scan dependency manifest files (requirements*.txt) for supply-chain issues.
        """
        path = Path(file_path)
        if not REQUIREMENTS_FILE_PATTERN.match(path.name):
            return []

        try:
            source_lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            return []

        vulnerabilities: list[VulnerabilityFound] = []
        seen: set[tuple[int, str]] = set()

        for index, raw_line in enumerate(source_lines, start=1):
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith(("-r", "--", "-e", "git+", "http://", "https://")):
                continue

            package = self._extract_package_name(line)
            if not package:
                continue

            if package in SUSPICIOUS_PACKAGES:
                self._add_unique(
                    vulnerabilities,
                    seen,
                    line=index,
                    code=raw_line.strip(),
                    source_lines=source_lines,
                    file_path=str(path),
                    confidence=0.9,
                    severity="high",
                    description=f"Dependency '{package}' looks suspicious or typosquatted.",
                )

            if not PIN_OPERATOR_PATTERN.search(line):
                self._add_unique(
                    vulnerabilities,
                    seen,
                    line=index,
                    code=raw_line.strip(),
                    source_lines=source_lines,
                    file_path=str(path),
                    confidence=0.68,
                    severity="medium",
                    description=f"Dependency '{package}' is unpinned; lock exact versions to reduce supply-chain risk.",
                )

        return vulnerabilities

    def _extract_package_name(self, requirement: str) -> str:
        candidate = requirement.split(";", 1)[0].strip()
        if not candidate:
            return ""
        name = re.split(r"[<>=!~@\[\s]", candidate, maxsplit=1)[0]
        return name.lower()

    def _is_exec_open_read(self, node: ast.AST) -> bool:
        """
        Match patterns like exec(open("payload.py").read()).
        """
        if not isinstance(node, ast.Call):
            return False

        if not isinstance(node.func, ast.Attribute):
            return False
        if node.func.attr != "read":
            return False

        open_call = node.func.value
        if not isinstance(open_call, ast.Call):
            return False
        return self._get_call_name(open_call.func) == "open"

    def _add_unique(
        self,
        vulnerabilities: list[VulnerabilityFound],
        seen: set[tuple[int, str]],
        line: int,
        code: str,
        source_lines: list[str],
        file_path: str,
        confidence: float,
        description: str,
        severity: str | None = None,
    ) -> None:
        key = (line, description)
        if key in seen:
            return
        seen.add(key)
        vulnerabilities.append(
            self._make_vuln(
                file_path=file_path,
                line_number=line,
                source_lines=source_lines,
                vulnerable_code=code,
                confidence=confidence,
                severity=severity,
                description=description,
            )
        )
