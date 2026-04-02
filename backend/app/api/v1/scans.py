import math
import os
import uuid
import shutil

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, Form
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.dependencies import get_current_user
from app.models.user import User
from app.models.project import Project
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.schemas.scan import ScanCreate, ScanResponse, ScanStatusResponse, ScanListResponse
from app.tasks.scan_tasks import run_scan_directory_task, run_scan_source_task
from app.utils.zip_handler import safe_extract_zip, ZipExtractionError

router = APIRouter()

@router.post("/projects/{project_id}/scans", response_model=ScanResponse, status_code=201)
async def create_scan(
    project_id: str,
    file: UploadFile | None = File(None),
    source_code: str | None = Form(None),
    scan_type: str = Form("manual"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = await db.get(Project, project_id)
    if not project or project.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Project not found")

    scan = Scan(project_id=project_id, scan_type=scan_type, status="queued")
    db.add(scan)
    await db.flush()
    await db.refresh(scan)

    # ✅ Commit BEFORE dispatching to Celery
    await db.commit()

    scan_id_str = str(scan.id)  # ✅ Convert UUID to string for Celery

    # Handle file upload
    if file:
        scan_dir = os.path.join(settings.SCAN_STORAGE_PATH, scan_id_str)
        os.makedirs(scan_dir, exist_ok=True)

        file_content = await file.read()
        if len(file_content) > settings.MAX_FILE_SIZE_MB * 1024 * 1024:
            raise HTTPException(status_code=413, detail="File too large")

        if file.filename and file.filename.endswith(".zip"):
            zip_path = os.path.join(scan_dir, "upload.zip")
            with open(zip_path, "wb") as f:
                f.write(file_content)
            try:
                extract_dir = safe_extract_zip(zip_path, scan_dir)
                run_scan_directory_task.delay(scan_id_str, extract_dir, project.language)
            except ZipExtractionError as e:
                raise HTTPException(status_code=400, detail=str(e))
        else:
            # Single file upload
            file_path = os.path.join(scan_dir, file.filename or "uploaded_file")
            with open(file_path, "wb") as f:
                f.write(file_content)
            run_scan_directory_task.delay(scan_id_str, scan_dir, project.language)

    elif source_code:
        run_scan_source_task.delay(scan_id_str, source_code, None, project.language)
    else:
        raise HTTPException(status_code=400, detail="Provide file upload or source_code")

    return ScanResponse(
        id=scan.id,
        project_id=scan.project_id,
        scan_type=scan.scan_type,
        status=scan.status,
        commit_hash=scan.commit_hash,
        branch_name=scan.branch_name,
        pr_number=scan.pr_number,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        total_files_scanned=scan.total_files_scanned,
        total_lines_scanned=scan.total_lines_scanned,
        overall_risk_score=scan.overall_risk_score,
        scan_duration_seconds=scan.scan_duration_seconds,
        created_at=scan.created_at,
    )


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Verify ownership
    project = await db.get(Project, scan.project_id)
    if not project or project.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Count vulnerabilities by severity
    result = await db.execute(
        select(Vulnerability.severity, func.count(Vulnerability.id))
        .where(Vulnerability.scan_id == scan_id)
        .group_by(Vulnerability.severity)
    )
    counts = dict(result.all())

    return ScanResponse(
        id=scan.id,
        project_id=scan.project_id,
        scan_type=scan.scan_type,
        status=scan.status,
        commit_hash=scan.commit_hash,
        branch_name=scan.branch_name,
        pr_number=scan.pr_number,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        total_files_scanned=scan.total_files_scanned,
        total_lines_scanned=scan.total_lines_scanned,
        overall_risk_score=scan.overall_risk_score,
        scan_duration_seconds=scan.scan_duration_seconds,
        created_at=scan.created_at,
        vulnerability_count=sum(counts.values()),
        critical_count=counts.get("critical", 0),
        high_count=counts.get("high", 0),
        medium_count=counts.get("medium", 0),
        low_count=counts.get("low", 0),
    )


@router.get("/scans/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    progress = 0.0
    if scan.status == "completed":
        progress = 100.0
    elif scan.status == "running":
        progress = 50.0
    elif scan.status == "failed":
        progress = 100.0

    return ScanStatusResponse(id=scan.id, status=scan.status, progress_percentage=progress)


@router.get("/projects/{project_id}/scans", response_model=ScanListResponse)
async def list_scans(
    project_id: str,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    status: str | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = await db.get(Project, project_id)
    if not project or project.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Project not found")

    q = select(Scan).where(Scan.project_id == project_id)
    if status:
        q = q.where(Scan.status == status)
    q = q.order_by(Scan.created_at.desc())

    count_q = select(func.count(Scan.id)).where(Scan.project_id == project_id)
    total = (await db.execute(count_q)).scalar() or 0

    result = await db.execute(q.offset((page - 1) * limit).limit(limit))
    scans = result.scalars().all()

    scan_responses = []
    for s in scans:
        sev_q = (
            select(Vulnerability.severity, func.count(Vulnerability.id))
            .where(Vulnerability.scan_id == s.id)
            .group_by(Vulnerability.severity)
        )
        counts = dict((await db.execute(sev_q)).all())
        scan_responses.append(
            ScanResponse(
                id=s.id,
                project_id=s.project_id,
                scan_type=s.scan_type,
                status=s.status,
                commit_hash=s.commit_hash,
                branch_name=s.branch_name,
                pr_number=s.pr_number,
                started_at=s.started_at,
                completed_at=s.completed_at,
                total_files_scanned=s.total_files_scanned,
                total_lines_scanned=s.total_lines_scanned,
                overall_risk_score=s.overall_risk_score,
                scan_duration_seconds=s.scan_duration_seconds,
                created_at=s.created_at,
                vulnerability_count=sum(counts.values()),
                critical_count=counts.get("critical", 0),
                high_count=counts.get("high", 0),
                medium_count=counts.get("medium", 0),
                low_count=counts.get("low", 0),
            )
        )

    return ScanListResponse(
        scans=scan_responses,
        total=total,
        page=page,
        pages=math.ceil(total / limit) if total > 0 else 1,
    )


@router.delete("/scans/{scan_id}")
async def delete_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    project = await db.get(Project, scan.project_id)
    if not project or project.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Scan not found")
    await db.delete(scan)
    return {"success": True}
