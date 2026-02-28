from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user
from app.models.user import User
from app.models.scan import Scan
from app.models.project import Project
from app.models.vulnerability import Vulnerability
from app.services.docker_service import sandbox_service

router = APIRouter(prefix="/sandbox")


@router.get("/status")
async def sandbox_status(current_user: User = Depends(get_current_user)):
    """Check if Docker sandbox is available."""
    return {
        "available": sandbox_service.is_available(),
        "enabled": sandbox_service.enabled,
    }


@router.post("/test/{scan_id}")
async def run_sandbox_test(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Run exploit simulation on a completed scan."""
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    project = await db.get(Project, scan.project_id)
    if not project or project.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status != "completed":
        raise HTTPException(status_code=400, detail="Scan not yet completed")

    if not sandbox_service.is_available():
        raise HTTPException(status_code=503, detail="Docker sandbox not available")

    # Get vulnerabilities
    result = await db.execute(
        select(Vulnerability).where(
            Vulnerability.scan_id == scan_id,
            Vulnerability.severity.in_(["critical", "high"]),
        )
    )
    vulns = result.scalars().all()

    vuln_dicts = [
        {
            "id": v.id,
            "vulnerability_type": v.vulnerability_type,
            "severity": v.severity,
            "code_snippet": v.code_snippet,
            "vulnerable_code": v.vulnerable_code,
        }
        for v in vulns
    ]

    # Run sandbox tests
    sandbox_result = sandbox_service.run_sandbox_tests(
        scan_id=scan_id,
        vulnerabilities=vuln_dicts,
        source_code=vulns[0].code_snippet if vulns else "",
    )

    # Update vulnerability confidence based on results
    for exploit_result in sandbox_result.results:
        if exploit_result.confirmed_exploitable:
            vuln = await db.get(Vulnerability, exploit_result.vulnerability_id)
            if vuln:
                vuln.confidence = 1.0  # Confirmed exploitable
                await db.flush()

    return {
        "scan_id": sandbox_result.scan_id,
        "total_tested": sandbox_result.total_tested,
        "confirmed_exploitable": sandbox_result.confirmed_count,
        "not_confirmed": sandbox_result.failed_count,
        "errors": sandbox_result.error_count,
        "results": [
            {
                "vulnerability_id": r.vulnerability_id,
                "vulnerability_type": r.vulnerability_type,
                "status": r.test_status,
                "exploitable": r.confirmed_exploitable,
                "payload": r.exploit_payload,
                "logs": r.container_logs[:1000],
                "time": r.execution_time_seconds,
            }
            for r in sandbox_result.results
        ],
    }
