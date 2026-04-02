"""Hardcoded secrets and credentials detector."""

import ast
import re

from app.core.detectors.base import BaseDetector, VulnerabilityFound

class HardcodedSecretsDetector(BaseDetector):

    SECRET_PATTERNS = [
        (r'(?i)(password|passwd|pwd)\s*=\s*["\']([^"\']{8,})["\']', "hardcoded_password"),
        (r'(?i)(secret|token|api_key|apikey)\s*=\s*["\']([^"\']{8,})["\']', "hardcoded_secret"),
        (r'(?i)(access_key|private_key)\s*=\s*["\']([^"\']{8,})["\']', "hardcoded_key"),
        (r'(AKIA[0-9A-Z]{12,})', "aws_access_key"),
        (r'(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*', "bearer_token"),
        (r'ghp_[a-zA-Z0-9]{36}', "github_pat"),
        (r'sk-[a-zA-Z0-9]{20,}', "openai_key"),
    ]

    SECRET_VARIABLE_NAMES = [
        "password", "passwd", "pwd", "secret", "token",
        "api_key", "apikey", "access_key", "private_key",
        "auth_token", "credentials", "db_password",
        "secret_key", "encryption_key",
    ]

    PLACEHOLDER_VALUES = {
        "changeme", "placeholder", "xxx", "your-",
        "todo", "fixme", "none", "null",
        "empty", "test", "fake", "dummy",
    }

    def _snippet(self, lines: list[str], lineno: int) -> str:
        start = max(0, lineno - 3)
        end = min(len(lines), lineno + 2)
        return "\n".join(lines[start:end])

    def _is_placeholder(self, value: str) -> bool:
        val = value.lower().strip().strip("\"'")
        return any(p in val for p in self.PLACEHOLDER_VALUES)

    def detect(
        self,
        tree: ast.AST,
        file_path: str,
        source_code: str,
        lines: list[str],
    ) -> list[VulnerabilityFound]:
        vulnerabilities = []
        seen_lines: set[int] = set()

        # --- Pass 1: Regex on raw lines ---
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            for pattern, label in self.SECRET_PATTERNS:
                match = re.search(pattern, line)
                if not match:
                    continue

                matched_text = match.group(0)
                if self._is_placeholder(matched_text):
                    continue

                if i not in seen_lines:
                    seen_lines.add(i)
                    vulnerabilities.append(
                        VulnerabilityFound(
                            file_path=file_path,
                            line_number=i,
                            end_line_number=i,  # Added
                            vulnerability_type="hardcoded_secret",
                            confidence=0.85,
                            code_snippet=self._snippet(lines, i),
                            vulnerable_code=stripped,
                            cwe_id="CWE-798",
                            severity="high",  # Added
                        )
                    )
                break

        # --- Pass 2: AST variable name check ---
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                var_name = target.id.lower()
                if not any(kw in var_name for kw in self.SECRET_VARIABLE_NAMES):
                    continue
                if not isinstance(node.value, ast.Constant):
                    continue
                if not isinstance(node.value.value, str):
                    continue

                value = node.value.value
                lineno = node.lineno

                if len(value) < 8 or self._is_placeholder(value):
                    continue
                if lineno in seen_lines:
                    continue

                seen_lines.add(lineno)
                vulnerabilities.append(
                    VulnerabilityFound(
                        file_path=file_path,
                        line_number=lineno,
                        end_line_number=lineno,  # Added
                        vulnerability_type="hardcoded_secret",
                        confidence=0.90,
                        code_snippet=self._snippet(lines, lineno),
                        vulnerable_code=lines[lineno - 1].strip() if lineno <= len(lines) else "",
                        cwe_id="CWE-798",
                        severity="high",  # Added
                    )
                )

        return vulnerabilities