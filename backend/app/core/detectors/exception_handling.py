"""Detector for mishandling exceptional conditions (OWASP A10:2025)."""

import ast

from app.core.detectors.base import BaseDetector, VulnerabilityFound

SENSITIVE_TERMS = {
    "traceback",
    "stack",
    "secret",
    "password",
    "token",
    "api_key",
    "private_key",
}


class ExceptionHandlingDetector(BaseDetector):
    name = "exception_mishandling"
    description = "Detects insecure exception handling patterns"
    default_severity = "medium"
    cwe_id = "CWE-755"

    def detect(
        self, tree: ast.AST, file_path: str, source_code: str, source_lines: list[str]
    ) -> list[VulnerabilityFound]:
        vulnerabilities: list[VulnerabilityFound] = []
        seen: set[tuple[int, str]] = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                if node.type is None:
                    self._add_unique(
                        vulnerabilities,
                        seen,
                        file_path,
                        source_lines,
                        node.lineno,
                        confidence=0.86,
                        severity="high",
                        description=(
                            "Bare except catches all exceptions and can hide security failures."
                        ),
                    )

                if self._is_silent_handler(node):
                    self._add_unique(
                        vulnerabilities,
                        seen,
                        file_path,
                        source_lines,
                        node.lineno,
                        confidence=0.84,
                        severity="high",
                        description=(
                            "Exception handler suppresses errors (pass/continue) and may create fail-open behavior."
                        ),
                    )

                if self._returns_allow_on_failure(node):
                    self._add_unique(
                        vulnerabilities,
                        seen,
                        file_path,
                        source_lines,
                        node.lineno,
                        confidence=0.74,
                        severity="medium",
                        description=(
                            "Exception path returns an allow/success value; this can bypass security controls."
                        ),
                    )

                if self._may_leak_exception_details(node):
                    self._add_unique(
                        vulnerabilities,
                        seen,
                        file_path,
                        source_lines,
                        node.lineno,
                        confidence=0.7,
                        severity="medium",
                        description=(
                            "Exception details may be exposed to callers, potentially leaking sensitive internals."
                        ),
                    )

            if isinstance(node, ast.Raise) and node.exc is not None:
                if self._raise_message_contains_sensitive_data(node.exc):
                    self._add_unique(
                        vulnerabilities,
                        seen,
                        file_path,
                        source_lines,
                        node.lineno,
                        confidence=0.68,
                        severity="medium",
                        description=(
                            "Raised exception message appears to include sensitive context (tokens, secrets, stack data)."
                        ),
                    )

        return vulnerabilities

    def _add_unique(
        self,
        vulnerabilities: list[VulnerabilityFound],
        seen: set[tuple[int, str]],
        file_path: str,
        source_lines: list[str],
        line_number: int,
        confidence: float,
        description: str,
        severity: str,
    ) -> None:
        key = (line_number, description)
        if key in seen:
            return
        seen.add(key)
        vulnerabilities.append(
            self._make_vuln(
                file_path=file_path,
                line_number=line_number,
                source_lines=source_lines,
                vulnerable_code=self._get_line_source(source_lines, line_number),
                confidence=confidence,
                severity=severity,
                description=description,
            )
        )

    def _is_silent_handler(self, node: ast.ExceptHandler) -> bool:
        if not node.body:
            return True
        return all(isinstance(stmt, (ast.Pass, ast.Continue)) for stmt in node.body)

    def _returns_allow_on_failure(self, node: ast.ExceptHandler) -> bool:
        for stmt in node.body:
            if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Constant):
                if stmt.value.value in (True, 1, "ok", "success", "allow"):
                    return True
        return False

    def _may_leak_exception_details(self, node: ast.ExceptHandler) -> bool:
        caught_name = node.name if isinstance(node.name, str) else None
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child.func) or ""
                if call_name in {"traceback.format_exc", "traceback.print_exc"}:
                    return True
            if isinstance(child, ast.Return) and child.value is not None:
                if self._expression_exposes_exception(child.value, caught_name):
                    return True
        return False

    def _expression_exposes_exception(self, value: ast.AST, caught_name: str | None) -> bool:
        text = self._safe_unparse(value).lower()
        if any(term in text for term in SENSITIVE_TERMS):
            return True

        if caught_name:
            if isinstance(value, ast.Name) and value.id == caught_name:
                return True
            if isinstance(value, ast.Call):
                call_name = self._get_call_name(value.func)
                if call_name in {"str", "repr"}:
                    for arg in value.args:
                        if isinstance(arg, ast.Name) and arg.id == caught_name:
                            return True

        return False

    def _raise_message_contains_sensitive_data(self, exc_node: ast.AST) -> bool:
        text = self._safe_unparse(exc_node).lower()
        return any(term in text for term in SENSITIVE_TERMS)

    def _safe_unparse(self, node: ast.AST) -> str:
        try:
            return ast.unparse(node)
        except Exception:
            return ""
