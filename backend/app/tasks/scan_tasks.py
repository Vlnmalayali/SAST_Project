"""Celery tasks for scanning operations."""

import asyncio
import logging
import os
import uuid as uuid_module

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.config import settings
from app.tasks import celery_app
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.models.taint_flow import TaintFlow
from app.core.scanner import CodeScanner
from app.core.scoring import calculate_cvss
from app.utils.helpers import extract_zip, cleanup_directory

from datetime import datetime, timezone

logger = logging.getLogger(__name__)

sync_engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)


@celery_app.task(bind=True, name="tasks.run_scan_directory")
def run_scan_directory_task(self, scan_id: str, directory: str, language: str = "python"):
    """Celery task to scan a directory."""
    scan_uuid = uuid_module.UUID(scan_id)  # ✅ Convert string to proper UUID

    with Session(sync_engine) as db:
        scan = db.get(Scan, scan_uuid)
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return

        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        db.commit()

        try:
            scanner = CodeScanner(language=language)
            result = scanner.scan_directory(directory, max_files=settings.MAX_FILES_PER_SCAN)

            # ✅ Insert vulnerabilities one at a time to avoid batch insert issues
            for vuln_found in result.vulnerabilities:
                cvss = calculate_cvss(vuln_found.vulnerability_type, vuln_found.confidence)
                vuln = Vulnerability(
                    id=uuid_module.uuid4(),        # ✅ Proper UUID object
                    scan_id=scan_uuid,             # ✅ Proper UUID object
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
                db.flush()  # ✅ Flush each one individually to avoid batch sentinel issue
                _persist_taint_flows(db, vuln.id, vuln_found.metadata)

            scan.status = "completed"
            scan.completed_at = datetime.now(timezone.utc)
            scan.total_files_scanned = result.total_files_scanned
            scan.total_lines_scanned = result.total_lines_scanned
            scan.overall_risk_score = result.overall_risk_score
            scan.scan_duration_seconds = int(result.scan_duration_seconds)
            db.commit()

            enrich_vulnerabilities_task.delay(scan_id)

            logger.info(
                f"Scan {scan_id} completed: {len(result.vulnerabilities)} vulnerabilities found"
            )

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
            db.rollback()  # ✅ Rollback before updating status
            scan.status = "failed"
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
        finally:
            cleanup_directory(directory)


@celery_app.task(bind=True, name="tasks.run_scan_source")
def run_scan_source_task(
    self,
    scan_id: str,
    source_code: str,
    file_name: str | None = None,
    language: str = "python",
):
    """Celery task to scan uploaded source code."""
    scan_dir = os.path.join(settings.SCAN_STORAGE_PATH, scan_id)
    os.makedirs(scan_dir, exist_ok=True)
    resolved_name = file_name or _default_source_filename(language)
    file_path = os.path.join(scan_dir, resolved_name)

    with open(file_path, "w") as f:
        f.write(source_code)

    run_scan_directory_task(scan_id, scan_dir, language)


@celery_app.task(name="tasks.enrich_vulnerabilities")
def enrich_vulnerabilities_task(scan_id: str):
    """Enrich vulnerabilities with AI explanations (runs after scan)."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        loop.run_until_complete(_enrich(scan_id))
    finally:
        loop.close()


def _persist_taint_flows(db: Session, vulnerability_id, metadata: dict | None) -> None:
    taint_flows = (metadata or {}).get("taint_flows", [])
    for flow in taint_flows:
        db.add(
            TaintFlow(
                vulnerability_id=vulnerability_id,
                source_file=flow.get("source_file", ""),
                source_line=flow.get("source_line", 0),
                source_type=flow.get("source_type", "unknown"),
                sink_file=flow.get("sink_file", ""),
                sink_line=flow.get("sink_line", 0),
                sink_type=flow.get("sink_type", "unknown"),
                flow_path={"steps": flow.get("flow_path", [])},
            )
        )


def _default_source_filename(language: str) -> str:
    language_map = {
        "python": "uploaded.py",
        "javascript": "uploaded.js",
        "java": "Uploaded.java",
    }
    return language_map.get((language or "python").strip().lower(), "uploaded.py")


async def _enrich(scan_id: str):
    from app.ai.openai_client import explain_vulnerability, suggest_fix
    from app.ai.response_parser import parse_explanation, parse_fix

    scan_uuid = uuid_module.UUID(scan_id)  # ✅ Convert here too

    with Session(sync_engine) as db:
        vulns = (
            db.query(Vulnerability)
            .filter(
                Vulnerability.scan_id == scan_uuid,
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
