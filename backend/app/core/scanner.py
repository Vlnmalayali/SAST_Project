"""Main scanner orchestrator — coordinates parsing, detection, scoring."""

import ast
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from app.core.ast_parser import PythonASTParser
from app.core.detectors import ALL_PYTHON_DETECTORS, VulnerabilityFound
from app.core.scoring import calculate_cvss, calculate_project_risk_score
from app.utils.helpers import discover_files

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
        self.language = language
        self.parser = PythonASTParser()
        self.detectors = ALL_PYTHON_DETECTORS

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

        # Calculate scores
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

    def scan_source(self, source_code: str, file_path: str = "<upload>") -> ScanResult:
        """Scan a single source code string."""
        start_time = time.time()
        result = ScanResult()

        try:
            parse_result = self.parser.parse_source(source_code, file_path)
            if parse_result is None:
                result.failed_files.append(file_path)
                return result

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

        # Score
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

    def _scan_file(self, file_path: str) -> list[VulnerabilityFound]:
        """Scan a single file with all detectors."""
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

        return all_vulns
