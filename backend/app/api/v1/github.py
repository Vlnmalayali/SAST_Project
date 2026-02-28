import os
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.config import settings
from app.database import get_db
from app.dependencies import get_current_user
from app.models.user import User
from app.models.project import Project
from app.models.scan import Scan
from app.services.github_service import (
    get_oauth_url,
    exchange_code_for_token,
    list_repos,
    clone_repository,
)
from app.tasks.scan_tasks import run_scan_directory_task

router = APIRouter(prefix="/github")


class GithubScanRequest(BaseModel):
    repo_full_name: str
    branch: str = "main"
    project_id: str
    pr_number: int | None = None


@router.get("/oauth")
async def github_oauth(current_user: User = Depends(get_current_user)):
    return {"auth_url": get_oauth_url()}


@router.get("/callback")
async def github_callback(
    code: str = Query(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    token = await exchange_code_for_token(code)
    if not token:
        raise HTTPException(status_code=400, detail="Failed to exchange code for token")
    current_user.github_token = token
    await db.flush()
    return {"success": True}


@router.get("/repos")
async def get_repos(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not current_user.github_token:
        raise HTTPException(status_code=400, detail="GitHub not connected")
    try:
        repos = list_repos(current_user.github_token)
        return {"repos": repos}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"GitHub API error: {str(e)}")


@router.post("/scan")
async def github_scan(
    data: GithubScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not current_user.github_token:
        raise HTTPException(status_code=400, detail="GitHub not connected")

    project = await db.get(Project, data.project_id)
    if not project or project.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Project not found")

    scan = Scan(
        project_id=data.project_id,
        scan_type="github",
        status="queued",
        branch_name=data.branch,
        pr_number=data.pr_number,
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)

    # Clone and scan
    scan_dir = os.path.join(settings.SCAN_STORAGE_PATH, scan.id)
    os.makedirs(scan_dir, exist_ok=True)

    try:
        repo_dir = clone_repository(
            current_user.github_token, data.repo_full_name, scan_dir, data.branch
        )
        run_scan_directory_task.delay(scan.id, repo_dir, project.language)
    except Exception as e:
        scan.status = "failed"
        await db.flush()
        raise HTTPException(status_code=502, detail=f"Clone failed: {str(e)}")

    return {"scan_id": scan.id, "status": "queued"}
