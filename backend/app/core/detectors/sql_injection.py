import ast
from app.core.detectors.base import BaseDetector, VulnerabilityFound

SQL_EXEC_METHODS = {
    "execute",
    "executemany",
    "executescript",
    "raw",
    "extra",
    "cursor.execute",
}

SQL_KEYWORDS = {"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "UNION"}


class SQLInjectionDetector(BaseDetector):
    name = "sql_injection"
    description = "Detects SQL injection vulnerabilities from string concatenation in queries"
    default_severity = "critical"
    cwe_id = "CWE-89"

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

            # Check if calling a SQL execution method
            method = func_name.split(".")[-1] if "." in func_name else func_name
            if method not in SQL_EXEC_METHODS:
                continue

            # Check if first argument uses string formatting with variables
            if not node.args:
                continue

            first_arg = node.args[0]
            if self._is_unsafe_sql(first_arg, source_lines):
                line_src = self._get_line_source(source_lines, node.lineno)
                confidence = 0.9 if self._is_string_concat_or_format(first_arg) else 0.6
                vulns.append(
                    self._make_vuln(
                        file_path=file_path,
                        line_number=node.lineno,
                        source_lines=source_lines,
                        vulnerable_code=line_src,
                        confidence=confidence,
                        description="SQL query constructed using string formatting with variables",
                    )
                )

        # Also detect SQL strings built with concatenation in assignments
        vulns.extend(self._detect_sql_string_building(tree, file_path, source_lines))
        return vulns

    def _is_unsafe_sql(self, node, source_lines: list[str]) -> bool:
        """Check if the SQL argument is built unsafely."""
        # f-string
        if isinstance(node, ast.JoinedStr):
            return self._looks_like_sql(node, source_lines)
        # String concatenation with +
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            if self._contains_name_reference(node) and self._looks_like_sql(node, source_lines):
                return True
        # % formatting
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                if self._has_sql_keyword(node.left.value):
                    return True
        # .format() call
        if isinstance(node, ast.Call):
            name = self._get_call_name(node.func)
            if name and name.endswith(".format"):
                return True
        # Variable reference (might be pre-built SQL string)
        if isinstance(node, ast.Name):
            return False  # Can't determine safety, low confidence handled elsewhere
        return False

    def _looks_like_sql(self, node, source_lines: list[str]) -> bool:
        """Check if the expression looks like it contains SQL."""
        line_src = self._get_line_source(source_lines, getattr(node, "lineno", 0))
        return self._has_sql_keyword(line_src)

    def _has_sql_keyword(self, text: str) -> bool:
        upper = text.upper()
        return any(kw in upper for kw in SQL_KEYWORDS)

    def _detect_sql_string_building(
        self, tree: ast.AST, file_path: str, source_lines: list[str]
    ) -> list[VulnerabilityFound]:
        """Detect SQL strings built across multiple lines."""
        vulns = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if not isinstance(node.value, (ast.BinOp, ast.JoinedStr)):
                continue
            line_src = self._get_line_source(source_lines, node.lineno)
            if self._has_sql_keyword(line_src) and self._contains_name_reference(node.value):
                vulns.append(
                    self._make_vuln(
                        file_path=file_path,
                        line_number=node.lineno,
                        source_lines=source_lines,
                        vulnerable_code=line_src,
                        confidence=0.6,
                        description="SQL string built with variable interpolation",
                    )
                )
        return vulns
