import ast
import re
from app.core.detectors.base import BaseDetector, VulnerabilityFound

SUSPICIOUS_NAMES = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "api_key",
    "apikey",
    "api_secret",
    "token",
    "access_token",
    "auth_token",
    "private_key",
    "secret_key",
    "aws_secret_access_key",
    "aws_access_key_id",
    "db_password",
    "database_password",
    "credentials",
    "connection_string",
}

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"(?i)(sk|pk)[-_]?(live|test)[-_]?[a-zA-Z0-9]{20,}", "API Secret Key"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
    (r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----", "Private Key"),
    (r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+", "JWT Token"),
    (r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*", "Bearer Token"),
]

PLACEHOLDER_VALUES = {
    "your_api_key",
    "your_secret",
    "changeme",
    "password",
    "xxx",
    "todo",
    "fixme",
    "replace_me",
    "your_api_key_here",
    "placeholder",
    "example",
    "test",
    "dummy",
    "",
    "none",
    "null",
}


class HardcodedSecretsDetector(BaseDetector):
    name = "hardcoded_secret"
    description = "Detects hardcoded passwords, API keys, and secrets"
    default_severity = "high"
    cwe_id = "CWE-798"

    def detect(
        self, tree: ast.AST, file_path: str, source_code: str, source_lines: list[str]
    ) -> list[VulnerabilityFound]:
        vulns = []

        # Skip test files
        if self._is_test_file(file_path):
            return vulns

        # Check assignments for hardcoded secrets
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                vulns.extend(self._check_assignment(node, file_path, source_lines))
            elif isinstance(node, ast.Call):
                vulns.extend(self._check_keyword_args(node, file_path, source_lines))

        # Regex-based pattern scanning
        vulns.extend(self._scan_patterns(source_code, source_lines, file_path))

        return vulns

    def _check_assignment(
        self, node: ast.Assign, file_path: str, source_lines: list[str]
    ) -> list[VulnerabilityFound]:
        vulns = []
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            var_name = target.id.lower()
            if not any(s in var_name for s in SUSPICIOUS_NAMES):
                continue
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                val = node.value.value.strip()
                if len(val) < 4 or val.lower() in PLACEHOLDER_VALUES:
                    continue
                vulns.append(
                    self._make_vuln(
                        file_path=file_path,
                        line_number=node.lineno,
                        source_lines=source_lines,
                        vulnerable_code=self._get_line_source(source_lines, node.lineno),
                        confidence=0.8,
                        description=f"Hardcoded secret in variable '{target.id}'",
                    )
                )
        return vulns

    def _check_keyword_args(
        self, node: ast.Call, file_path: str, source_lines: list[str]
    ) -> list[VulnerabilityFound]:
        vulns = []
        for kw in node.keywords:
            if kw.arg and kw.arg.lower() in SUSPICIOUS_NAMES:
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    val = kw.value.value.strip()
                    if len(val) >= 4 and val.lower() not in PLACEHOLDER_VALUES:
                        vulns.append(
                            self._make_vuln(
                                file_path=file_path,
                                line_number=node.lineno,
                                source_lines=source_lines,
                                vulnerable_code=self._get_line_source(source_lines, node.lineno),
                                confidence=0.7,
                                description=f"Hardcoded secret in keyword arg '{kw.arg}'",
                            )
                        )
        return vulns

    def _scan_patterns(
        self, source_code: str, source_lines: list[str], file_path: str
    ) -> list[VulnerabilityFound]:
        vulns = []
        for pattern, label in SECRET_PATTERNS:
            for match in re.finditer(pattern, source_code):
                line_num = source_code[: match.start()].count("\n") + 1
                vulns.append(
                    self._make_vuln(
                        file_path=file_path,
                        line_number=line_num,
                        source_lines=source_lines,
                        vulnerable_code=self._get_line_source(source_lines, line_num),
                        confidence=0.85,
                        severity="critical" if "Private Key" in label else "high",
                        description=f"Detected {label} pattern in source code",
                    )
                )
        return vulns

    def _is_test_file(self, path: str) -> bool:
        lower = path.lower()
        return "test" in lower or "example" in lower or "fixture" in lower
