import ast
from app.core.detectors.base import BaseDetector, VulnerabilityFound

USER_INPUT_ATTRS = {
    "request.GET",
    "request.POST",
    "request.args",
    "request.form",
    "request.data",
    "request.json",
    "request.values",
    "request.query_string",
}

UNSAFE_RENDER_FUNCS = {"HttpResponse", "make_response"}
UNSAFE_TEMPLATE_FILTERS = {"safe", "mark_safe", "Markup"}


class XSSDetector(BaseDetector):
    name = "xss"
    description = "Detects Cross-Site Scripting vulnerabilities"
    default_severity = "high"
    cwe_id = "CWE-79"

    def detect(
        self, tree: ast.AST, file_path: str, source_code: str, source_lines: list[str]
    ) -> list[VulnerabilityFound]:
        vulns = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func_name = self._get_call_name(node.func)
            if not func_name:
                continue

            # Direct HTML response with user input
            if func_name.split(".")[-1] in UNSAFE_RENDER_FUNCS:
                if node.args and self._contains_user_input_or_format(node.args[0], source_lines):
                    vulns.append(
                        self._make_vuln(
                            file_path=file_path,
                            line_number=node.lineno,
                            source_lines=source_lines,
                            vulnerable_code=self._get_line_source(source_lines, node.lineno),
                            confidence=0.8,
                            description="User input rendered directly in HTTP response",
                        )
                    )

            # mark_safe / Markup with variables
            if func_name.split(".")[-1] in UNSAFE_TEMPLATE_FILTERS:
                if node.args and self._contains_name_reference(node.args[0]):
                    vulns.append(
                        self._make_vuln(
                            file_path=file_path,
                            line_number=node.lineno,
                            source_lines=source_lines,
                            vulnerable_code=self._get_line_source(source_lines, node.lineno),
                            confidence=0.85,
                            description="Variable marked as safe without sanitization",
                        )
                    )

            # render_template with |safe in source
            if func_name in ("render_template", "render_template_string"):
                if func_name == "render_template_string" and node.args:
                    if self._contains_name_reference(node.args[0]):
                        vulns.append(
                            self._make_vuln(
                                file_path=file_path,
                                line_number=node.lineno,
                                source_lines=source_lines,
                                vulnerable_code=self._get_line_source(source_lines, node.lineno),
                                confidence=0.85,
                                description="Template string rendered with variable content",
                            )
                        )

        # Detect f-strings containing HTML with variables
        vulns.extend(self._detect_html_fstrings(tree, file_path, source_lines))
        return vulns

    def _contains_user_input_or_format(self, node, source_lines: list[str]) -> bool:
        if self._is_string_concat_or_format(node) and self._contains_name_reference(node):
            return True
        line = self._get_line_source(source_lines, getattr(node, "lineno", 0))
        return any(inp in line for inp in USER_INPUT_ATTRS)

    def _detect_html_fstrings(
        self, tree: ast.AST, file_path: str, source_lines: list[str]
    ) -> list[VulnerabilityFound]:
        vulns = []
        for node in ast.walk(tree):
            if isinstance(node, ast.JoinedStr):
                line = self._get_line_source(source_lines, node.lineno)
                if "<" in line and ">" in line and self._contains_name_reference(node):
                    vulns.append(
                        self._make_vuln(
                            file_path=file_path,
                            line_number=node.lineno,
                            source_lines=source_lines,
                            vulnerable_code=line,
                            confidence=0.7,
                            description="HTML content built with f-string and variables",
                        )
                    )
        return vulns
