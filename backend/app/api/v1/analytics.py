from collections import Counter
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user
from app.models.user import User
from app.models.project import Project
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability

router = APIRouter(prefix="/analytics")


@router.get("/risk-trend")
async def risk_trend(
    project_id: str = Query(...),
    time_range: str = Query("30d"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = await db.get(Project, project_id)
    if not project or project.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Project not found")

    result = await db.execute(
        select(Scan.created_at, Scan.overall_risk_score)
        .where(Scan.project_id == project_id, Scan.status == "completed")
        .order_by(Scan.created_at.asc())
        .limit(100)
    )
    data = [{"date": row[0].isoformat(), "risk_score": row[1]} for row in result.all()]
    return {"data": data}


@router.get("/vulnerability-distribution")
async def vulnerability_distribution(
    project_id: str = Query(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = await db.get(Project, project_id)
    if not project or project.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Project not found")

    # Get latest scan
    latest_scan = (
        await db.execute(
            select(Scan)
            .where(Scan.project_id == project_id, Scan.status == "completed")
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    if not latest_scan:
        return {"distribution": {}}

    result = await db.execute(
        select(Vulnerability.vulnerability_type, func.count(Vulnerability.id))
        .where(Vulnerability.scan_id == latest_scan.id)
        .group_by(Vulnerability.vulnerability_type)
    )
    return {"distribution": dict(result.all())}


@router.get("/severity-distribution")
async def severity_distribution(
    project_id: str = Query(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = await db.get(Project, project_id)
    if not project or project.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Project not found")

    latest_scan = (
        await db.execute(
            select(Scan)
            .where(Scan.project_id == project_id, Scan.status == "completed")
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    if not latest_scan:
        return {"distribution": {}}

    result = await db.execute(
        select(Vulnerability.severity, func.count(Vulnerability.id))
        .where(Vulnerability.scan_id == latest_scan.id)
        .group_by(Vulnerability.severity)
    )
    return {"distribution": dict(result.all())}


@router.get("/summary")
async def project_summary(
    project_id: str = Query(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = await db.get(Project, project_id)
    if not project or project.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Project not found")

    total_scans = (
        await db.execute(select(func.count(Scan.id)).where(Scan.project_id == project_id))
    ).scalar() or 0

    completed_scans = (
        await db.execute(
            select(func.count(Scan.id)).where(
                Scan.project_id == project_id, Scan.status == "completed"
            )
        )
    ).scalar() or 0

    # Latest scan info
    latest = (
        await db.execute(
            select(Scan)
            .where(Scan.project_id == project_id, Scan.status == "completed")
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    latest_vulns = 0
    if latest:
        latest_vulns = (
            await db.execute(
                select(func.count(Vulnerability.id)).where(Vulnerability.scan_id == latest.id)
            )
        ).scalar() or 0

    # First scan for comparison
    first = (
        await db.execute(
            select(Scan)
            .where(Scan.project_id == project_id, Scan.status == "completed")
            .order_by(Scan.created_at.asc())
            .limit(1)
        )
    ).scalar_one_or_none()

    improvement = None
    if first and latest and first.id != latest.id:
        if first.overall_risk_score > 0:
            improvement = round(
                ((first.overall_risk_score - latest.overall_risk_score) / first.overall_risk_score)
                * 100,
                1,
            )

    return {
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "latest_risk_score": latest.overall_risk_score if latest else None,
        "latest_vulnerability_count": latest_vulns,
        "risk_improvement_percentage": improvement,
    }


@router.get("/comparison")
async def compare_scans(
    project_id: str = Query(...),
    scan_id_1: str = Query(..., alias="scan1"),
    scan_id_2: str = Query(..., alias="scan2"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Compare two scans side by side."""
    project = await db.get(Project, project_id)
    if not project or project.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Project not found")

    # Fetch vulnerabilities from both scans
    result1 = await db.execute(select(Vulnerability).where(Vulnerability.scan_id == scan_id_1))
    vulns1 = result1.scalars().all()

    result2 = await db.execute(select(Vulnerability).where(Vulnerability.scan_id == scan_id_2))
    vulns2 = result2.scalars().all()

    # Build fingerprint sets for comparison: (file_path, line_number, vuln_type)
    def fingerprint(v):
        return f"{v.file_path}:{v.line_number}:{v.vulnerability_type}"

    set1 = {fingerprint(v): v for v in vulns1}
    set2 = {fingerprint(v): v for v in vulns2}

    keys1 = set(set1.keys())
    keys2 = set(set2.keys())

    fixed = keys1 - keys2  # In scan1 but not scan2 = fixed
    new_vulns = keys2 - keys1  # In scan2 but not scan1 = new
    unchanged = keys1 & keys2  # In both

    def vuln_summary(v):
        return {
            "id": v.id,
            "file_path": v.file_path,
            "line_number": v.line_number,
            "vulnerability_type": v.vulnerability_type,
            "severity": v.severity,
            "cvss_score": v.cvss_score,
        }

    # Severity count comparison
    sev1 = Counter(v.severity for v in vulns1)
    sev2 = Counter(v.severity for v in vulns2)

    scan1_obj = await db.get(Scan, scan_id_1)
    scan2_obj = await db.get(Scan, scan_id_2)

    return {
        "scan1": {
            "id": scan_id_1,
            "date": scan1_obj.created_at.isoformat() if scan1_obj else None,
            "risk_score": scan1_obj.overall_risk_score if scan1_obj else 0,
            "total_vulnerabilities": len(vulns1),
            "severity_counts": dict(sev1),
        },
        "scan2": {
            "id": scan_id_2,
            "date": scan2_obj.created_at.isoformat() if scan2_obj else None,
            "risk_score": scan2_obj.overall_risk_score if scan2_obj else 0,
            "total_vulnerabilities": len(vulns2),
            "severity_counts": dict(sev2),
        },
        "fixed_vulnerabilities": [vuln_summary(set1[k]) for k in fixed],
        "new_vulnerabilities": [vuln_summary(set2[k]) for k in new_vulns],
        "unchanged_count": len(unchanged),
        "improvement": {
            "fixed_count": len(fixed),
            "new_count": len(new_vulns),
            "risk_change": round(
                (scan2_obj.overall_risk_score if scan2_obj else 0)
                - (scan1_obj.overall_risk_score if scan1_obj else 0),
                1,
            ),
        },
    }
