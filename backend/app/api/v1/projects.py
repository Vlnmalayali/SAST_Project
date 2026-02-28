import math
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user
from app.models.user import User
from app.models.project import Project
from app.models.scan import Scan
from app.schemas.project import (
    ProjectCreate,
    ProjectUpdate,
    ProjectResponse,
    ProjectListResponse,
)

router = APIRouter(prefix="/projects")


@router.get("", response_model=ProjectListResponse)
async def list_projects(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    offset = (page - 1) * limit

    count_q = select(func.count(Project.id)).where(Project.user_id == current_user.id)
    total = (await db.execute(count_q)).scalar() or 0

    q = (
        select(Project)
        .where(Project.user_id == current_user.id)
        .order_by(Project.updated_at.desc())
        .offset(offset)
        .limit(limit)
    )
    result = await db.execute(q)
    projects = result.scalars().all()

    project_responses = []
    for proj in projects:
        # Get latest scan info
        scan_q = (
            select(Scan).where(Scan.project_id == proj.id).order_by(Scan.created_at.desc()).limit(1)
        )
        latest_scan = (await db.execute(scan_q)).scalar_one_or_none()
        scan_count_q = select(func.count(Scan.id)).where(Scan.project_id == proj.id)
        scan_count = (await db.execute(scan_count_q)).scalar() or 0

        project_responses.append(
            ProjectResponse(
                id=proj.id,
                name=proj.name,
                description=proj.description,
                repository_url=proj.repository_url,
                language=proj.language,
                created_at=proj.created_at,
                updated_at=proj.updated_at,
                last_scanned_at=proj.last_scanned_at,
                scan_count=scan_count,
                latest_risk_score=latest_scan.overall_risk_score if latest_scan else None,
            )
        )

    return ProjectListResponse(
        projects=project_responses,
        total=total,
        page=page,
        pages=math.ceil(total / limit) if total > 0 else 1,
    )


@router.post("", response_model=ProjectResponse, status_code=201)
async def create_project(
    data: ProjectCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = Project(
        user_id=current_user.id,
        name=data.name,
        description=data.description,
        repository_url=data.repository_url,
        language=data.language,
    )
    db.add(project)
    await db.flush()
    await db.refresh(project)

    return ProjectResponse(
        id=project.id,
        name=project.name,
        description=project.description,
        repository_url=project.repository_url,
        language=project.language,
        created_at=project.created_at,
        updated_at=project.updated_at,
        last_scanned_at=project.last_scanned_at,
    )


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = await db.get(Project, project_id)
    if not project or project.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Project not found")

    scan_count_q = select(func.count(Scan.id)).where(Scan.project_id == project.id)
    scan_count = (await db.execute(scan_count_q)).scalar() or 0

    latest_q = (
        select(Scan).where(Scan.project_id == project.id).order_by(Scan.created_at.desc()).limit(1)
    )
    latest_scan = (await db.execute(latest_q)).scalar_one_or_none()

    return ProjectResponse(
        id=project.id,
        name=project.name,
        description=project.description,
        repository_url=project.repository_url,
        language=project.language,
        created_at=project.created_at,
        updated_at=project.updated_at,
        last_scanned_at=project.last_scanned_at,
        scan_count=scan_count,
        latest_risk_score=latest_scan.overall_risk_score if latest_scan else None,
    )


@router.patch("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: str,
    data: ProjectUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = await db.get(Project, project_id)
    if not project or project.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Project not found")

    update_data = data.model_dump(exclude_unset=True)
    for key, val in update_data.items():
        setattr(project, key, val)

    await db.flush()
    await db.refresh(project)

    return ProjectResponse(
        id=project.id,
        name=project.name,
        description=project.description,
        repository_url=project.repository_url,
        language=project.language,
        created_at=project.created_at,
        updated_at=project.updated_at,
        last_scanned_at=project.last_scanned_at,
    )


@router.delete("/{project_id}")
async def delete_project(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = await db.get(Project, project_id)
    if not project or project.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Project not found")
    await db.delete(project)
    return {"success": True}
