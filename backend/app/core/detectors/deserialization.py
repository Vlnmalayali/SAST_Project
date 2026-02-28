import ast
from app.core.detectors.base import BaseDetector, VulnerabilityFound

UNSAFE_DESERIALIZERS = {
    "pickle.loads",
    "pickle.load",
    "cPickle.loads",
    "cPickle.load",
    "shelve.open",
    "marshal.loads",
    "marshal.load",
}


class InsecureDeserializationDetector(BaseDetector):
    name = "insecure_deserialization"
    description = "Detects insecure deserialization of untrusted data"
    default_severity = "critical"
    cwe_id = "CWE-502"

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

            # Unsafe pickle/marshal/shelve
            if func_name in UNSAFE_DESERIALIZERS:
                vulns.append(
                    self._make_vuln(
                        file_path=file_path,
                        line_number=node.lineno,
                        source_lines=source_lines,
                        vulnerable_code=self._get_line_source(source_lines, node.lineno),
                        confidence=0.85,
                        description=f"Insecure deserialization via {func_name}",
                    )
                )

            # yaml.load without SafeLoader
            if func_name in ("yaml.load", "yaml.load_all"):
                has_safe_loader = False
                for kw in node.keywords:
                    if kw.arg == "Loader":
                        loader_name = self._get_call_name(kw.value) or ""
                        if "Safe" in loader_name or "BaseLoader" in loader_name:
                            has_safe_loader = True
                if not has_safe_loader:
                    vulns.append(
                        self._make_vuln(
                            file_path=file_path,
                            line_number=node.lineno,
                            source_lines=source_lines,
                            vulnerable_code=self._get_line_source(source_lines, node.lineno),
                            confidence=0.9,
                            description="yaml.load without SafeLoader allows arbitrary code execution",
                        )
                    )

        return vulns
