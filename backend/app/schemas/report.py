from datetime import datetime
from pydantic import BaseModel


class ReportCreate(BaseModel):
    report_type: str = "pdf"


class ReportResponse(BaseModel):
    id: str
    scan_id: str
    report_type: str
    file_path: str
    file_size_bytes: int
    generated_at: datetime

    model_config = {"from_attributes": True}
