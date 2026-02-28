import ast
from app.core.detectors.base import BaseDetector, VulnerabilityFound

WEAK_HASHES = {"md5", "sha1", "md4", "md2"}
WEAK_CIPHERS = {"DES", "RC4", "RC2", "Blowfish"}


class WeakCryptoDetector(BaseDetector):
    name = "weak_crypto"
    description = "Detects use of weak cryptographic algorithms"
    default_severity = "medium"
    cwe_id = "CWE-327"

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

            # hashlib.md5(), hashlib.sha1()
            if func_name.startswith("hashlib."):
                algo = func_name.split(".")[-1].lower()
                if algo in WEAK_HASHES:
                    vulns.append(
                        self._make_vuln(
                            file_path=file_path,
                            line_number=node.lineno,
                            source_lines=source_lines,
                            vulnerable_code=self._get_line_source(source_lines, node.lineno),
                            confidence=0.85,
                            description=f"Weak hash algorithm {algo} detected",
                        )
                    )

            # hashlib.new("md5")
            if func_name == "hashlib.new" and node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                    if first_arg.value.lower() in WEAK_HASHES:
                        vulns.append(
                            self._make_vuln(
                                file_path=file_path,
                                line_number=node.lineno,
                                source_lines=source_lines,
                                vulnerable_code=self._get_line_source(source_lines, node.lineno),
                                confidence=0.85,
                                description=f"Weak hash algorithm {first_arg.value} via hashlib.new",
                            )
                        )

            # Direct md5(), sha1() calls (from imports)
            if func_name.lower() in WEAK_HASHES:
                vulns.append(
                    self._make_vuln(
                        file_path=file_path,
                        line_number=node.lineno,
                        source_lines=source_lines,
                        vulnerable_code=self._get_line_source(source_lines, node.lineno),
                        confidence=0.7,
                        description=f"Direct use of weak hash function {func_name}",
                    )
                )

        return vulns
