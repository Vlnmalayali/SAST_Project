from datetime import datetime
from pydantic import BaseModel


class ScanCreate(BaseModel):
    scan_type: str = "manual"
    branch_name: str | None = None
    commit_hash: str | None = None


class ScanResponse(BaseModel):
    id: str
    project_id: str
    scan_type: str
    status: str
    commit_hash: str | None
    branch_name: str | None
    pr_number: int | None
    started_at: datetime | None
    completed_at: datetime | None
    total_files_scanned: int
    total_lines_scanned: int
    overall_risk_score: float
    scan_duration_seconds: int | None
    created_at: datetime
    vulnerability_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    model_config = {"from_attributes": True}


class ScanStatusResponse(BaseModel):
    id: str
    status: str
    progress_percentage: float = 0.0
    current_file: str | None = None


class ScanListResponse(BaseModel):
    scans: list[ScanResponse]
    total: int
    page: int
    pages: int
