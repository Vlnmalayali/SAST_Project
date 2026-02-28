import uuid
from datetime import datetime

from sqlalchemy import String, Integer, Float, Boolean, DateTime, ForeignKey, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class TaintFlow(Base):
    __tablename__ = "taint_flows"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    vulnerability_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("vulnerabilities.id", ondelete="CASCADE")
    )
    source_file: Mapped[str] = mapped_column(String(500), nullable=False)
    source_line: Mapped[int] = mapped_column(Integer, nullable=False)
    source_type: Mapped[str] = mapped_column(String(100), nullable=False)
    sink_file: Mapped[str] = mapped_column(String(500), nullable=False)
    sink_line: Mapped[int] = mapped_column(Integer, nullable=False)
    sink_type: Mapped[str] = mapped_column(String(100), nullable=False)
    flow_path: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    vulnerability = relationship("Vulnerability", back_populates="taint_flows")


class ScanMetric(Base):
    __tablename__ = "scan_metrics"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    scan_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("scans.id", ondelete="CASCADE")
    )
    metric_name: Mapped[str] = mapped_column(String(100), nullable=False)
    metric_value: Mapped[float] = mapped_column(Float, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scan = relationship("Scan", back_populates="metrics")


class CICDIntegration(Base):
    __tablename__ = "cicd_integrations"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    project_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("projects.id", ondelete="CASCADE")
    )
    integration_type: Mapped[str] = mapped_column(String(50), nullable=False)
    webhook_url: Mapped[str] = mapped_column(String(500), nullable=False)
    secret_token: Mapped[str] = mapped_column(String(255), nullable=False)
    block_on_critical: Mapped[bool] = mapped_column(Boolean, default=True)
    block_on_high: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    project = relationship("Project", back_populates="cicd_integrations")
