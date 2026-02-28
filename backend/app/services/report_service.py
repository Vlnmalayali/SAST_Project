"""Report generation service."""

import logging
import os
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.report import Report
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.reporting.pdf_generator import generate_pdf_report

logger = logging.getLogger(__name__)


async def generate_report(db: AsyncSession, scan_id: str, report_type: str = "pdf") -> Report:
    """Generate a report for a scan."""
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise ValueError(f"Scan {scan_id} not found")

    result = await db.execute(
        select(Vulnerability)
        .where(Vulnerability.scan_id == scan_id)
        .order_by(Vulnerability.severity)
    )
    vulnerabilities = result.scalars().all()

    # Generate PDF
    report_dir = settings.report_path
    file_name = f"report_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    file_path = os.path.join(str(report_dir), file_name)

    generate_pdf_report(
        file_path=file_path,
        scan=scan,
        vulnerabilities=list(vulnerabilities),
    )

    file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

    report = Report(
        scan_id=scan_id,
        report_type=report_type,
        file_path=file_path,
        file_size_bytes=file_size,
    )
    db.add(report)
    await db.flush()
    await db.refresh(report)

    return report
