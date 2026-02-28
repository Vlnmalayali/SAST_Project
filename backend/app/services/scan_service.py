"""Scan orchestration service — bridges API with core scanning engine."""

import logging
import os
import shutil
import tempfile
import uuid
from datetime import datetime, timezone

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.scanner import CodeScanner
from app.core.taint_analysis import TaintAnalyzer
from app.ai.openai_client import explain_vulnerability, suggest_fix
from app.ai.response_parser import parse_explanation, parse_fix
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.models.taint_flow import TaintFlow

logger = logging.getLogger(__name__)


async def create_scan(db: AsyncSession, project_id: str, scan_type: str = "manual") -> Scan:
    """Create a new scan record."""
    scan = Scan(
        project_id=project_id,
        scan_type=scan_type,
        status="queued",
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)
    return scan


async def run_scan_on_directory(
    db: AsyncSession,
    scan_id: str,
    directory: str,
    language: str = "python",
) -> Scan:
    """Execute a scan on a directory and save results."""
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise ValueError(f"Scan {scan_id} not found")

    scan.status = "running"
    scan.started_at = datetime.now(timezone.utc)
    await db.flush()

    try:
        # Run core scanner
        scanner = CodeScanner(language=language)
        result = scanner.scan_directory(directory, max_files=settings.MAX_FILES_PER_SCAN)

        # Run taint analysis
        TaintAnalyzer()

        # Save vulnerabilities
        for vuln_found in result.vulnerabilities:
            explanation_data = await explain_vulnerability(
                vulnerability_type=vuln_found.vulnerability_type,
                file_path=vuln_found.file_path,
                line_number=vuln_found.line_number,
                code_snippet=vuln_found.code_snippet,
            )
            parsed_explanation = parse_explanation(explanation_data)

            fix_data = await suggest_fix(
                vulnerability_type=vuln_found.vulnerability_type,
                vulnerable_code=vuln_found.vulnerable_code,
                description=vuln_found.description,
            )
            parsed_fix = parse_fix(fix_data)

            vuln = Vulnerability(
                scan_id=scan_id,
                file_path=vuln_found.file_path,
                line_number=vuln_found.line_number,
                end_line_number=vuln_found.end_line_number,
                vulnerability_type=vuln_found.vulnerability_type,
                severity=vuln_found.severity,
                cvss_score=vuln_found.metadata.get("cvss_score", 5.0),
                confidence=vuln_found.confidence,
                code_snippet=vuln_found.code_snippet,
                vulnerable_code=vuln_found.vulnerable_code,
                ai_explanation=parsed_explanation.get("explanation"),
                ai_fixed_code=parsed_fix.get("fixed_code"),
                remediation_steps=parsed_fix if parsed_fix.get("remediation_steps") else None,
                cwe_id=parsed_explanation.get("cwe") or vuln_found.cwe_id,
            )
            db.add(vuln)

        # Update scan record
        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.total_files_scanned = result.total_files_scanned
        scan.total_lines_scanned = result.total_lines_scanned
        scan.overall_risk_score = result.overall_risk_score
        scan.scan_duration_seconds = int(result.scan_duration_seconds)

        await db.flush()

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
        scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        await db.flush()
        raise

    return scan


async def run_scan_on_source(
    db: AsyncSession,
    scan_id: str,
    source_code: str,
    file_name: str = "uploaded_code.py",
) -> Scan:
    """Execute a scan on uploaded source code."""
    # Write source to temp file and scan as directory
    scan_dir = os.path.join(settings.SCAN_STORAGE_PATH, scan_id)
    os.makedirs(scan_dir, exist_ok=True)
    file_path = os.path.join(scan_dir, file_name)

    try:
        with open(file_path, "w") as f:
            f.write(source_code)
        return await run_scan_on_directory(db, scan_id, scan_dir)
    finally:
        shutil.rmtree(scan_dir, ignore_errors=True)


async def get_scan_with_counts(db: AsyncSession, scan_id: str) -> dict | None:
    """Get scan with vulnerability counts."""
    scan = await db.get(Scan, scan_id)
    if not scan:
        return None

    result = await db.execute(
        select(
            Vulnerability.severity,
            func.count(Vulnerability.id),
        )
        .where(Vulnerability.scan_id == scan_id)
        .group_by(Vulnerability.severity)
    )
    severity_counts = dict(result.all())

    return {
        "scan": scan,
        "vulnerability_count": sum(severity_counts.values()),
        "critical_count": severity_counts.get("critical", 0),
        "high_count": severity_counts.get("high", 0),
        "medium_count": severity_counts.get("medium", 0),
        "low_count": severity_counts.get("low", 0),
    }
