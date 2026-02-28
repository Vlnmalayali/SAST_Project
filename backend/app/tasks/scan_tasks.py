"""Celery tasks for scanning operations."""

import asyncio
import logging
import os
import shutil

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.config import settings
from app.tasks import celery_app
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.core.scanner import CodeScanner
from app.core.scoring import calculate_cvss
from app.utils.helpers import extract_zip, cleanup_directory

from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Synchronous engine for Celery (Celery workers can't use async)
sync_engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)


@celery_app.task(bind=True, name="tasks.run_scan_directory")
def run_scan_directory_task(self, scan_id: str, directory: str, language: str = "python"):
    """Celery task to scan a directory."""
    with Session(sync_engine) as db:
        scan = db.get(Scan, scan_id)
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return

        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        db.commit()

        try:
            scanner = CodeScanner(language=language)
            result = scanner.scan_directory(directory, max_files=settings.MAX_FILES_PER_SCAN)

            for vuln_found in result.vulnerabilities:
                cvss = calculate_cvss(vuln_found.vulnerability_type, vuln_found.confidence)
                vuln = Vulnerability(
                    scan_id=scan_id,
                    file_path=vuln_found.file_path,
                    line_number=vuln_found.line_number,
                    end_line_number=vuln_found.end_line_number,
                    vulnerability_type=vuln_found.vulnerability_type,
                    severity=cvss.severity,
                    cvss_score=cvss.base_score,
                    confidence=vuln_found.confidence,
                    code_snippet=vuln_found.code_snippet,
                    vulnerable_code=vuln_found.vulnerable_code,
                    cwe_id=vuln_found.cwe_id,
                )
                db.add(vuln)

            scan.status = "completed"
            scan.completed_at = datetime.now(timezone.utc)
            scan.total_files_scanned = result.total_files_scanned
            scan.total_lines_scanned = result.total_lines_scanned
            scan.overall_risk_score = result.overall_risk_score
            scan.scan_duration_seconds = int(result.scan_duration_seconds)
            db.commit()

            # Trigger AI enrichment asynchronously
            enrich_vulnerabilities_task.delay(scan_id)

            logger.info(
                f"Scan {scan_id} completed: {len(result.vulnerabilities)} vulnerabilities found"
            )

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
            scan.status = "failed"
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
        finally:
            cleanup_directory(directory)


@celery_app.task(bind=True, name="tasks.run_scan_source")
def run_scan_source_task(self, scan_id: str, source_code: str, file_name: str = "uploaded.py"):
    """Celery task to scan uploaded source code."""
    scan_dir = os.path.join(settings.SCAN_STORAGE_PATH, scan_id)
    os.makedirs(scan_dir, exist_ok=True)
    file_path = os.path.join(scan_dir, file_name)

    with open(file_path, "w") as f:
        f.write(source_code)

    run_scan_directory_task(scan_id, scan_dir)


@celery_app.task(name="tasks.enrich_vulnerabilities")
def enrich_vulnerabilities_task(scan_id: str):
    """Enrich vulnerabilities with AI explanations (runs after scan)."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        loop.run_until_complete(_enrich(scan_id))
    finally:
        loop.close()


async def _enrich(scan_id: str):
    from app.ai.openai_client import explain_vulnerability, suggest_fix
    from app.ai.response_parser import parse_explanation, parse_fix

    with Session(sync_engine) as db:
        vulns = (
            db.query(Vulnerability)
            .filter(
                Vulnerability.scan_id == scan_id,
                Vulnerability.ai_explanation.is_(None),
            )
            .all()
        )

        for vuln in vulns:
            try:
                explanation_data = await explain_vulnerability(
                    vulnerability_type=vuln.vulnerability_type,
                    file_path=vuln.file_path,
                    line_number=vuln.line_number,
                    code_snippet=vuln.code_snippet,
                )
                parsed = parse_explanation(explanation_data)
                vuln.ai_explanation = parsed["explanation"]
                if parsed["cwe"]:
                    vuln.cwe_id = parsed["cwe"]

                fix_data = await suggest_fix(
                    vulnerability_type=vuln.vulnerability_type,
                    vulnerable_code=vuln.vulnerable_code,
                    description=parsed.get("explanation", ""),
                )
                parsed_fix = parse_fix(fix_data)
                vuln.ai_fixed_code = parsed_fix.get("fixed_code")
                if parsed_fix.get("remediation_steps"):
                    vuln.remediation_steps = parsed_fix

            except Exception as e:
                logger.warning(f"AI enrichment failed for vuln {vuln.id}: {e}")

        db.commit()
