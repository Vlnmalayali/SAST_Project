import ast
from app.core.detectors.base import BaseDetector, VulnerabilityFound

FILE_OPEN_FUNCS = {"open", "builtins.open", "io.open"}
PATH_FUNCS = {"os.path.join", "pathlib.Path"}


class PathTraversalDetector(BaseDetector):
    name = "path_traversal"
    description = "Detects path traversal vulnerabilities in file operations"
    default_severity = "high"
    cwe_id = "CWE-22"

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

            # open() with variable path
            if func_name in FILE_OPEN_FUNCS or func_name == "open":
                if node.args and self._contains_name_reference(node.args[0]):
                    # Check if argument is just a constant
                    if not isinstance(node.args[0], ast.Constant):
                        vulns.append(
                            self._make_vuln(
                                file_path=file_path,
                                line_number=node.lineno,
                                source_lines=source_lines,
                                vulnerable_code=self._get_line_source(source_lines, node.lineno),
                                confidence=0.6,
                                description="File opened with variable path — potential path traversal",
                            )
                        )

            # os.path.join with user input then open
            if func_name == "os.path.join":
                if len(node.args) >= 2 and self._contains_name_reference(node.args[-1]):
                    vulns.append(
                        self._make_vuln(
                            file_path=file_path,
                            line_number=node.lineno,
                            source_lines=source_lines,
                            vulnerable_code=self._get_line_source(source_lines, node.lineno),
                            confidence=0.55,
                            description="os.path.join with variable component — validate path",
                        )
                    )

            # shutil operations with variables
            if func_name.startswith("shutil.") and node.args:
                if self._contains_name_reference(node.args[0]):
                    vulns.append(
                        self._make_vuln(
                            file_path=file_path,
                            line_number=node.lineno,
                            source_lines=source_lines,
                            vulnerable_code=self._get_line_source(source_lines, node.lineno),
                            confidence=0.5,
                            severity="medium",
                            description=f"File operation {func_name} with variable path",
                        )
                    )

        return vulns
