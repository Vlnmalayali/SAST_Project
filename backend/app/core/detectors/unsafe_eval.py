import ast
from app.core.detectors.base import BaseDetector, VulnerabilityFound

DANGEROUS_BUILTINS = {"eval", "exec", "compile", "__import__"}


class UnsafeEvalDetector(BaseDetector):
    name = "unsafe_eval"
    description = "Detects use of eval/exec with potentially untrusted input"
    default_severity = "critical"
    cwe_id = "CWE-95"

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

            bare_name = func_name.split(".")[-1]
            if bare_name not in DANGEROUS_BUILTINS:
                continue

            # ast.literal_eval is safe
            if func_name == "ast.literal_eval":
                continue

            # Check if argument is a constant (less dangerous)
            if node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, ast.Constant):
                    confidence = 0.4  # Static string in eval - still bad practice but less risky
                else:
                    confidence = 0.9  # Variable input - very dangerous
            else:
                confidence = 0.5

            vulns.append(
                self._make_vuln(
                    file_path=file_path,
                    line_number=node.lineno,
                    source_lines=source_lines,
                    vulnerable_code=self._get_line_source(source_lines, node.lineno),
                    confidence=confidence,
                    description=f"Use of {func_name}() can execute arbitrary code",
                )
            )

        return vulns
