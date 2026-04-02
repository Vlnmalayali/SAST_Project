"""Lightweight, language-agnostic taint scanning for non-Python source files."""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.core.detectors.base import VulnerabilityFound
from app.utils.helpers import get_code_snippet
from app.core.taint_rules import load_taint_rules, normalize_taint_language


@dataclass
class _TaintOrigin:
    source_line: int
    source_type: str
    variable_name: str
    flow_path: list[dict]


class TextTaintScanner:
    """
    Regex-based taint scanner for languages without AST support yet.

    This is intentionally conservative and is designed as a bridge while full
    language parsers are being integrated.
    """

    _ASSIGN_RE = re.compile(r"^\s*(?:const|let|var|final|[\w<>\[\]]+\s+)?([A-Za-z_]\w*)\s*=\s*(.+)$")
    _WORD_TEMPLATE = r"\b{}\b"

    def __init__(self, language: str):
        self.language = normalize_taint_language(language)
        rules = load_taint_rules(self.language)
        self.sources = rules.sources
        self.sinks = rules.sinks
        self.sanitizers = rules.sanitizers

    def scan_source(self, source_code: str, file_path: str) -> list[VulnerabilityFound]:
        lines = source_code.splitlines()
        tainted_vars: dict[str, _TaintOrigin] = {}
        findings: list[VulnerabilityFound] = []
        seen_keys: set[tuple] = set()

        for line_number, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("//"):
                continue

            self._update_assignments(line, line_number, file_path, tainted_vars)
            line_tainted_origins = self._tainted_origins_in_line(line, tainted_vars)

            if not line_tainted_origins:
                continue

            for sink_pattern, vuln_type in self.sinks.items():
                if sink_pattern not in line:
                    continue

                for origin in line_tainted_origins:
                    key = (origin.source_line, line_number, vuln_type, sink_pattern)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)

                    flow_path = [dict(step) for step in origin.flow_path]
                    flow_path.append(
                        {
                            "file": file_path,
                            "line": line_number,
                            "variable": sink_pattern,
                            "operation": "sink",
                        }
                    )

                    findings.append(
                        VulnerabilityFound(
                            file_path=file_path,
                            line_number=line_number,
                            end_line_number=None,
                            vulnerability_type=vuln_type,
                            severity="high",
                            confidence=0.72,
                            code_snippet=get_code_snippet(lines, line_number),
                            vulnerable_code=raw_line.strip(),
                            cwe_id=None,
                            description=(
                                "Heuristic taint flow detected in non-Python source "
                                f"from {origin.source_type} to {sink_pattern}."
                            ),
                            metadata={
                                "detection_mode": "text_taint",
                                "taint_flows": [
                                    {
                                        "source_file": file_path,
                                        "source_line": origin.source_line,
                                        "source_type": origin.source_type,
                                        "sink_file": file_path,
                                        "sink_line": line_number,
                                        "sink_type": vuln_type,
                                        "flow_path": flow_path,
                                    }
                                ],
                            },
                        )
                    )

        return findings

    def _update_assignments(
        self,
        line: str,
        line_number: int,
        file_path: str,
        tainted_vars: dict[str, _TaintOrigin],
    ) -> None:
        match = self._ASSIGN_RE.match(line)
        if not match:
            return

        var_name = match.group(1)
        rhs = match.group(2)

        if self._contains_any(rhs, self.sources):
            tainted_vars[var_name] = _TaintOrigin(
                source_line=line_number,
                source_type=self._matched_source(rhs),
                variable_name=var_name,
                flow_path=[
                    {
                        "file": file_path,
                        "line": line_number,
                        "variable": var_name,
                        "operation": "source",
                    }
                ],
            )
            return

        if self._contains_any(rhs, self.sanitizers):
            tainted_vars.pop(var_name, None)
            return

        origin = self._first_tainted_origin(rhs, tainted_vars)
        if origin is None:
            return

        flow_path = [dict(step) for step in origin.flow_path]
        flow_path.append(
            {
                "file": file_path,
                "line": line_number,
                "variable": var_name,
                "operation": "assign",
            }
        )
        tainted_vars[var_name] = _TaintOrigin(
            source_line=origin.source_line,
            source_type=origin.source_type,
            variable_name=var_name,
            flow_path=flow_path,
        )

    def _tainted_origins_in_line(
        self, line: str, tainted_vars: dict[str, _TaintOrigin]
    ) -> list[_TaintOrigin]:
        origins: list[_TaintOrigin] = []
        for var_name, origin in tainted_vars.items():
            if re.search(self._WORD_TEMPLATE.format(re.escape(var_name)), line):
                origins.append(origin)
        return origins

    def _first_tainted_origin(
        self, rhs: str, tainted_vars: dict[str, _TaintOrigin]
    ) -> _TaintOrigin | None:
        for var_name, origin in tainted_vars.items():
            if re.search(self._WORD_TEMPLATE.format(re.escape(var_name)), rhs):
                return origin
        return None

    def _contains_any(self, text: str, patterns: set[str]) -> bool:
        return any(pattern in text for pattern in patterns)

    def _matched_source(self, text: str) -> str:
        for source in self.sources:
            if source in text:
                return source
        return "user_input"
