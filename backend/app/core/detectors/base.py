import ast
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from app.utils.helpers import get_code_snippet


@dataclass
class VulnerabilityFound:
    file_path: str
    line_number: int
    end_line_number: int | None
    vulnerability_type: str
    severity: str
    confidence: float
    code_snippet: str
    vulnerable_code: str
    cwe_id: str | None = None
    description: str = ""
    metadata: dict = field(default_factory=dict)


class BaseDetector(ABC):
    name: str = "base"
    description: str = ""
    default_severity: str = "medium"
    cwe_id: str | None = None

    @abstractmethod
    def detect(
        self, tree: ast.AST, file_path: str, source_code: str, source_lines: list[str]
    ) -> list[VulnerabilityFound]:
        """Analyze AST and return list of found vulnerabilities."""
        ...

    def _make_vuln(
        self,
        file_path: str,
        line_number: int,
        source_lines: list[str],
        vulnerable_code: str,
        confidence: float = 0.7,
        severity: str | None = None,
        cwe_id: str | None = None,
        end_line: int | None = None,
        description: str = "",
        metadata: dict | None = None,
    ) -> VulnerabilityFound:
        return VulnerabilityFound(
            file_path=file_path,
            line_number=line_number,
            end_line_number=end_line,
            vulnerability_type=self.name,
            severity=severity or self.default_severity,
            confidence=confidence,
            code_snippet=get_code_snippet(source_lines, line_number),
            vulnerable_code=vulnerable_code,
            cwe_id=cwe_id or self.cwe_id,
            description=description,
            metadata=metadata or {},
        )

    def _get_call_name(self, node) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val = self._get_call_name(node.value)
            if val:
                return f"{val}.{node.attr}"
            return node.attr
        return None

    def _is_string_concat_or_format(self, node) -> bool:
        """Check if a node involves string concatenation, f-string, or format."""
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return True
        if isinstance(node, ast.Call):
            name = self._get_call_name(node.func)
            if name and name.endswith(".format"):
                return True
        return False

    def _contains_name_reference(self, node) -> bool:
        """Check if an expression references any variable names (not just constants)."""
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                return True
        return False

    def _get_line_source(self, source_lines: list[str], lineno: int) -> str:
        if 0 < lineno <= len(source_lines):
            return source_lines[lineno - 1].strip()
        return ""
