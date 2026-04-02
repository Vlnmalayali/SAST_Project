import math
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.compliance_mapping import get_compliance_mapping
from app.database import get_db
from app.dependencies import get_current_user
from app.models.user import User
from app.models.project import Project
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.models.taint_flow import TaintFlow
from app.schemas.vulnerability import (
    VulnerabilityResponse,
    VulnerabilityUpdate,
    VulnerabilityListResponse,
    TaintFlowResponse,
)

router = APIRouter()


def _to_vulnerability_response(vuln: Vulnerability) -> VulnerabilityResponse:
    payload = VulnerabilityResponse.model_validate(vuln).model_dump()
    payload["compliance"] = get_compliance_mapping(
        vulnerability_type=vuln.vulnerability_type,
        cwe_id=vuln.cwe_id,
    )
    return VulnerabilityResponse(**payload)


@router.get("/scans/{scan_id}/vulnerabilities", response_model=VulnerabilityListResponse)
async def list_vulnerabilities(
    scan_id: str,
    severity: str | None = None,
    vuln_type: str | None = Query(None, alias="type"),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    project = await db.get(Project, scan.project_id)
    if not project or project.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Scan not found")

    q = select(Vulnerability).where(Vulnerability.scan_id == scan_id)
    count_q = select(func.count(Vulnerability.id)).where(Vulnerability.scan_id == scan_id)

    if severity:
        q = q.where(Vulnerability.severity == severity)
        count_q = count_q.where(Vulnerability.severity == severity)
    if vuln_type:
        q = q.where(Vulnerability.vulnerability_type == vuln_type)
        count_q = count_q.where(Vulnerability.vulnerability_type == vuln_type)

    total = (await db.execute(count_q)).scalar() or 0
    q = q.order_by(Vulnerability.cvss_score.desc()).offset((page - 1) * limit).limit(limit)
    result = await db.execute(q)

    return VulnerabilityListResponse(
        vulnerabilities=[_to_vulnerability_response(v) for v in result.scalars().all()],
        total=total,
        page=page,
        pages=math.ceil(total / limit) if total > 0 else 1,
    )


@router.get("/vulnerabilities/{vuln_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(
    vuln_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    vuln = await db.get(Vulnerability, vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return _to_vulnerability_response(vuln)


@router.patch("/vulnerabilities/{vuln_id}", response_model=VulnerabilityResponse)
async def update_vulnerability(
    vuln_id: str,
    data: VulnerabilityUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    vuln = await db.get(Vulnerability, vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    update = data.model_dump(exclude_unset=True)
    for key, val in update.items():
        setattr(vuln, key, val)
    await db.flush()
    await db.refresh(vuln)
    return _to_vulnerability_response(vuln)


@router.get("/vulnerabilities/{vuln_id}/taint-flows", response_model=list[TaintFlowResponse])
async def get_taint_flows(
    vuln_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(TaintFlow).where(TaintFlow.vulnerability_id == vuln_id))
    return [TaintFlowResponse.model_validate(tf) for tf in result.scalars().all()]


@router.post("/vulnerabilities/{vuln_id}/regenerate-fix")
async def regenerate_fix(
    vuln_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    vuln = await db.get(Vulnerability, vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    from app.ai.openai_client import suggest_fix
    from app.ai.response_parser import parse_fix

    fix_data = await suggest_fix(
        vulnerability_type=vuln.vulnerability_type,
        vulnerable_code=vuln.vulnerable_code,
        description=vuln.ai_explanation or "",
    )
    parsed = parse_fix(fix_data)
    vuln.ai_fixed_code = parsed.get("fixed_code")
    vuln.remediation_steps = parsed if parsed.get("remediation_steps") else vuln.remediation_steps
    await db.flush()
    await db.refresh(vuln)

    return {
        "ai_fixed_code": vuln.ai_fixed_code,
        "remediation_steps": vuln.remediation_steps,
    }
