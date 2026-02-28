"""Celery tasks for report generation."""

import logging
import os
from collections import Counter
from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.config import settings
from app.tasks import celery_app
from app.models.report import Report
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.reporting.pdf_generator import generate_pdf_report

logger = logging.getLogger(__name__)
sync_engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)


@celery_app.task(name="tasks.generate_report")
def generate_report_task(scan_id: str, report_type: str = "pdf") -> str | None:
    """Generate a PDF report for a scan."""
    with Session(sync_engine) as db:
        scan = db.get(Scan, scan_id)
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return None

        vulns = (
            db.query(Vulnerability)
            .filter(Vulnerability.scan_id == scan_id)
            .order_by(Vulnerability.severity)
            .all()
        )

        report_dir = settings.report_path
        file_name = f"report_{scan_id[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        file_path = os.path.join(str(report_dir), file_name)

        try:
            generate_pdf_report(file_path=file_path, scan=scan, vulnerabilities=vulns)

            file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
            report = Report(
                scan_id=scan_id,
                report_type=report_type,
                file_path=file_path,
                file_size_bytes=file_size,
            )
            db.add(report)
            db.commit()
            db.refresh(report)
            logger.info(f"Report generated: {file_path}")
            return report.id

        except Exception as e:
            logger.error(f"Report generation failed for scan {scan_id}: {e}", exc_info=True)
            return None
