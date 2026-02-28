from datetime import datetime
from pydantic import BaseModel, Field


class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    repository_url: str | None = None
    language: str = "python"


class ProjectUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    repository_url: str | None = None
    language: str | None = None


class ProjectResponse(BaseModel):
    id: str
    name: str
    description: str | None
    repository_url: str | None
    language: str
    created_at: datetime
    updated_at: datetime
    last_scanned_at: datetime | None
    scan_count: int = 0
    latest_risk_score: float | None = None

    model_config = {"from_attributes": True}


class ProjectListResponse(BaseModel):
    projects: list[ProjectResponse]
    total: int
    page: int
    pages: int
