import ast

from app.core.detectors.base import BaseDetector, VulnerabilityFound
from app.core.taint_analysis import TaintAnalyzer
from app.utils.helpers import get_code_snippet

CWE_BY_TYPE = {
    "sql_injection": "CWE-89",
    "command_injection": "CWE-78",
    "unsafe_eval": "CWE-95",
    "path_traversal": "CWE-22",
    "insecure_deserialization": "CWE-502",
}


class TaintFlowDetector(BaseDetector):
    """
    Emits vulnerabilities discovered by interprocedural taint tracking.

    We intentionally map findings to the sink vulnerability type (`sql_injection`,
    `command_injection`, etc.) so existing severity/CVSS handling still applies.
    """

    name = "taint_flow"
    description = "Interprocedural source-to-sink taint tracking"
    default_severity = "high"

    def __init__(self, language: str = "python") -> None:
        self.language = language
        self._analyzer = TaintAnalyzer(language=language)

    def detect(
        self, tree: ast.AST, file_path: str, source_code: str, source_lines: list[str]
    ) -> list[VulnerabilityFound]:
        flows = self._analyzer.analyze(tree, file_path, source_lines)
        vulnerabilities: list[VulnerabilityFound] = []

        for flow in flows:
            line_text = ""
            if 0 < flow.sink_line <= len(source_lines):
                line_text = source_lines[flow.sink_line - 1].strip()

            vulnerabilities.append(
                VulnerabilityFound(
                    file_path=file_path,
                    line_number=flow.sink_line,
                    end_line_number=None,
                    vulnerability_type=flow.sink_type,
                    severity="high",
                    confidence=0.92,
                    code_snippet=get_code_snippet(source_lines, flow.sink_line),
                    vulnerable_code=line_text,
                    cwe_id=CWE_BY_TYPE.get(flow.sink_type),
                    description=(
                        "Tainted data reaches a dangerous sink via interprocedural flow "
                        f"from {flow.source_type}."
                    ),
                    metadata={
                        "taint_flows": [
                            {
                                "source_file": flow.source_file,
                                "source_line": flow.source_line,
                                "source_type": flow.source_type,
                                "sink_file": flow.sink_file,
                                "sink_line": flow.sink_line,
                                "sink_type": flow.sink_type,
                                "flow_path": flow.flow_path,
                            }
                        ]
                    },
                )
            )

        return vulnerabilities
