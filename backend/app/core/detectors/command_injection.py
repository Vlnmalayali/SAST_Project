import ast
from app.core.detectors.base import BaseDetector, VulnerabilityFound

DANGEROUS_FUNCS = {
    "os.system",
    "os.popen",
    "os.popen2",
    "os.popen3",
    "os.popen4",
    "subprocess.call",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.check_output",
    "subprocess.check_call",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
    "commands.getoutput",
    "commands.getstatusoutput",
}

ALWAYS_DANGEROUS = {"os.system", "os.popen", "commands.getoutput", "commands.getstatusoutput"}


class CommandInjectionDetector(BaseDetector):
    name = "command_injection"
    description = "Detects command injection vulnerabilities"
    default_severity = "critical"
    cwe_id = "CWE-78"

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

            if func_name in ALWAYS_DANGEROUS:
                # os.system, os.popen always take shell commands
                if node.args and self._arg_has_variable(node.args[0]):
                    vulns.append(
                        self._make_vuln(
                            file_path=file_path,
                            line_number=node.lineno,
                            source_lines=source_lines,
                            vulnerable_code=self._get_line_source(source_lines, node.lineno),
                            confidence=0.9,
                            description=f"Variable used in shell command via {func_name}",
                        )
                    )

            elif func_name in DANGEROUS_FUNCS:
                # subprocess functions: check for shell=True with string arg
                shell_true = self._has_shell_true(node)
                if shell_true and node.args:
                    first_arg = node.args[0]
                    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                        continue  # Static string, likely safe
                    if self._arg_has_variable(first_arg):
                        vulns.append(
                            self._make_vuln(
                                file_path=file_path,
                                line_number=node.lineno,
                                source_lines=source_lines,
                                vulnerable_code=self._get_line_source(source_lines, node.lineno),
                                confidence=0.85,
                                description=f"shell=True with variable command in {func_name}",
                            )
                        )

        return vulns

    def _has_shell_true(self, call_node: ast.Call) -> bool:
        for kw in call_node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
        return False

    def _arg_has_variable(self, node) -> bool:
        if isinstance(node, ast.Name):
            return True
        if isinstance(node, ast.JoinedStr):
            return self._contains_name_reference(node)
        if isinstance(node, ast.BinOp):
            return self._contains_name_reference(node)
        if isinstance(node, ast.Call):
            name = self._get_call_name(node.func)
            if name and name.endswith(".format"):
                return True
        return False
