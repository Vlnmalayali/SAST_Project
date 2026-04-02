"""Main scanner orchestrator — coordinates parsing, detection, scoring."""

import io
import logging
import re
import time
import tokenize
from dataclasses import dataclass, field
from pathlib import Path

from app.core.ast_parser import PythonASTParser
from app.core.detectors import VulnerabilityFound, get_detectors_for_language
from app.core.scoring import calculate_cvss, calculate_project_risk_score
from app.core.text_taint_scanner import TextTaintScanner
from app.utils.helpers import EXCLUDE_DIRS, discover_files

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    vulnerabilities: list[VulnerabilityFound] = field(default_factory=list)
    total_files_scanned: int = 0
    total_lines_scanned: int = 0
    scan_duration_seconds: float = 0.0
    overall_risk_score: float = 0.0
    failed_files: list[str] = field(default_factory=list)
    severity_counts: dict = field(
        default_factory=lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    )


class CodeScanner:
    """Orchestrates the full scanning process."""

    def __init__(self, language: str = "python"):
        self.language = (language or "python").strip().lower()
        self.parser = PythonASTParser() if self.language == "python" else None
        self.detectors = get_detectors_for_language(self.language) if self.language == "python" else []
        self.text_taint_scanner = (
            None if self.language == "python" else TextTaintScanner(language=self.language)
        )

    def scan_directory(self, directory: str, max_files: int = 1000) -> ScanResult:
        """Scan all code files in a directory."""
        start_time = time.time()
        result = ScanResult()

        files = discover_files(directory, self.language)
        if len(files) > max_files:
            logger.warning(f"Too many files ({len(files)}), limiting to {max_files}")
            files = files[:max_files]

        for file_path in files:
            try:
                file_vulns = self._scan_file(file_path)
                result.vulnerabilities.extend(file_vulns)
                line_count = len(Path(file_path).read_text(errors="ignore").splitlines())
                result.total_lines_scanned += line_count
                result.total_files_scanned += 1
            except Exception as e:
                logger.error(f"Error scanning {file_path}: {e}")
                result.failed_files.append(file_path)

        if self.language == "python":
            manifest_vulns, manifest_files = self._scan_dependency_manifests(directory)
            result.vulnerabilities.extend(manifest_vulns)
            for manifest_file in manifest_files:
                try:
                    line_count = len(Path(manifest_file).read_text(errors="ignore").splitlines())
                    result.total_lines_scanned += line_count
                    result.total_files_scanned += 1
                except Exception as e:
                    logger.warning(f"Unable to count lines for manifest {manifest_file}: {e}")

        return self._finalize_result(result, start_time)

    def scan_source(self, source_code: str, file_path: str = "<upload>") -> ScanResult:
        """Scan a single source code string."""
        start_time = time.time()
        result = ScanResult()

        try:
            if self.language != "python":
                result.vulnerabilities = self._deduplicate_vulnerabilities(
                    self.text_taint_scanner.scan_source(source_code, file_path)
                    if self.text_taint_scanner
                    else []
                )
                result.total_files_scanned = 1
                result.total_lines_scanned = len(source_code.splitlines())
                return self._finalize_result(
                    result,
                    start_time,
                    source_overrides={file_path: source_code},
                )

            parse_result = self.parser.parse_source(source_code, file_path)
            if parse_result is None:
                result.failed_files.append(file_path)
                return self._finalize_result(
                    result,
                    start_time,
                    source_overrides={file_path: source_code},
                )

            for detector in self.detectors:
                try:
                    vulns = detector.detect(
                        parse_result.ast_tree, file_path, source_code, parse_result.source_lines
                    )
                    result.vulnerabilities.extend(vulns)
                except Exception as e:
                    logger.error(f"Detector {detector.name} failed on {file_path}: {e}")

            result.total_files_scanned = 1
            result.total_lines_scanned = len(parse_result.source_lines)
        except Exception as e:
            logger.error(f"Error scanning source: {e}")
            result.failed_files.append(file_path)

        return self._finalize_result(
            result,
            start_time,
            source_overrides={file_path: source_code},
        )

    def _scan_file(self, file_path: str) -> list[VulnerabilityFound]:
        """Scan a single file with all detectors."""
        if self.language != "python":
            if self.text_taint_scanner is None:
                return []
            source_code = Path(file_path).read_text(encoding="utf-8", errors="ignore")
            return self.text_taint_scanner.scan_source(source_code, file_path)

        parse_result = self.parser.parse_file(file_path)
        if parse_result is None:
            return []

        all_vulns = []
        for detector in self.detectors:
            try:
                vulns = detector.detect(
                    parse_result.ast_tree,
                    file_path,
                    parse_result.source_code,
                    parse_result.source_lines,
                )
                all_vulns.extend(vulns)
            except Exception as e:
                logger.error(f"Detector {detector.name} failed on {file_path}: {e}")

        return self._deduplicate_vulnerabilities(all_vulns)

    def _scan_dependency_manifests(self, directory: str) -> tuple[list[VulnerabilityFound], list[str]]:
        """
        Scan requirements manifests for supply-chain findings (OWASP A03:2025).
        """
        manifest_paths: list[Path] = []
        root = Path(directory)
        for path in root.rglob("requirements*.txt"):
            if any(excluded in path.parts for excluded in EXCLUDE_DIRS):
                continue
            if path.is_file():
                manifest_paths.append(path)

        if not manifest_paths:
            return [], []

        vulnerabilities: list[VulnerabilityFound] = []
        for detector in self.detectors:
            scan_manifest = getattr(detector, "scan_manifest_file", None)
            if not callable(scan_manifest):
                continue
            for manifest in manifest_paths:
                try:
                    vulnerabilities.extend(scan_manifest(str(manifest)))
                except Exception as e:
                    logger.error(f"Detector {detector.name} failed on manifest {manifest}: {e}")

        return vulnerabilities, [str(path) for path in manifest_paths]

    def _finalize_result(
        self,
        result: ScanResult,
        start_time: float,
        source_overrides: dict[str, str] | None = None,
    ) -> ScanResult:
        result.vulnerabilities = self._apply_inline_suppressions(
            result.vulnerabilities,
            source_overrides=source_overrides or {},
        )
        result.vulnerabilities = self._deduplicate_vulnerabilities(result.vulnerabilities)
        for vuln in result.vulnerabilities:
            cvss = calculate_cvss(vuln.vulnerability_type, vuln.confidence)
            vuln.metadata["cvss_score"] = cvss.base_score
            vuln.severity = cvss.severity
            result.severity_counts[cvss.severity] = result.severity_counts.get(cvss.severity, 0) + 1

        vuln_scores = [
            {"severity": v.severity, "cvss_score": v.metadata.get("cvss_score", 5.0)}
            for v in result.vulnerabilities
        ]
        result.overall_risk_score = calculate_project_risk_score(vuln_scores)
        result.scan_duration_seconds = round(time.time() - start_time, 2)
        return result

    def _apply_inline_suppressions(
        self,
        vulnerabilities: list[VulnerabilityFound],
        source_overrides: dict[str, str],
    ) -> list[VulnerabilityFound]:
        """
        Support inline suppression using `nosast` comments.

        Examples:
        - Python: `cursor.execute(query)  # nosast`
        - JS/TS/Java: `eval(x); // nosast`
        """
        suppressed_cache: dict[str, set[int]] = {}
        filtered: list[VulnerabilityFound] = []

        for vuln in vulnerabilities:
            file_path = vuln.file_path
            if file_path not in suppressed_cache:
                source_code = source_overrides.get(file_path)
                if source_code is None:
                    try:
                        source_code = Path(file_path).read_text(encoding="utf-8", errors="ignore")
                    except Exception:
                        source_code = ""
                suppressed_cache[file_path] = self._get_suppressed_lines(source_code)

            if vuln.line_number in suppressed_cache[file_path]:
                continue
            filtered.append(vuln)

        return filtered

    def _get_suppressed_lines(self, source_code: str) -> set[int]:
        suppressed: set[int] = set()
        if not source_code:
            return suppressed

        marker = "nosast"
        if self.language == "python":
            try:
                tokens = tokenize.generate_tokens(io.StringIO(source_code).readline)
                for token in tokens:
                    if token.type == tokenize.COMMENT and marker in token.string.lower():
                        suppressed.add(token.start[0])
                return suppressed
            except tokenize.TokenError:
                # Fall back to line scanning for malformed source.
                pass

        for line_number, line in enumerate(source_code.splitlines(), start=1):
            if re.search(r"(#|//).*nosast", line, flags=re.IGNORECASE):
                suppressed.add(line_number)
        return suppressed

    def _deduplicate_vulnerabilities(
        self, vulnerabilities: list[VulnerabilityFound]
    ) -> list[VulnerabilityFound]:
        """
        Merge duplicate findings emitted by multiple detectors.

        Taint-aware and syntax-based detectors may report the same sink line; we keep one
        canonical finding (highest confidence) and merge trace metadata.
        """
        deduped: dict[tuple, VulnerabilityFound] = {}

        for vuln in vulnerabilities:
            key = (
                vuln.file_path,
                vuln.line_number,
                vuln.vulnerability_type,
                vuln.vulnerable_code.strip(),
            )
            existing = deduped.get(key)
            if existing is None:
                deduped[key] = vuln
                continue

            # Keep the strongest confidence record as canonical.
            if vuln.confidence > existing.confidence:
                keep, other = vuln, existing
            else:
                keep, other = existing, vuln

            keep.metadata = self._merge_metadata(keep.metadata, other.metadata)
            deduped[key] = keep

        return sorted(
            deduped.values(),
            key=lambda v: (v.file_path, v.line_number, v.vulnerability_type),
        )

    def _merge_metadata(self, primary: dict | None, secondary: dict | None) -> dict:
        merged: dict = dict(primary or {})
        other = secondary or {}

        primary_flows = merged.get("taint_flows", [])
        secondary_flows = other.get("taint_flows", [])
        if primary_flows or secondary_flows:
            seen = set()
            merged_flows = []
            for flow in [*primary_flows, *secondary_flows]:
                key = (
                    flow.get("source_file"),
                    flow.get("source_line"),
                    flow.get("sink_file"),
                    flow.get("sink_line"),
                    flow.get("sink_type"),
                )
                if key in seen:
                    continue
                seen.add(key)
                merged_flows.append(flow)
            merged["taint_flows"] = merged_flows

        for key, value in other.items():
            merged.setdefault(key, value)

        return merged
