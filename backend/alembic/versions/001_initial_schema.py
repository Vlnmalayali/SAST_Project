"""initial schema

Revision ID: 001
Revises:
Create Date: 2024-01-01 00:00:00.000000
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("email", sa.String(255), unique=True, index=True, nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(255), nullable=False),
        sa.Column("github_token", sa.String(500), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "projects",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("user_id", UUID(as_uuid=False), sa.ForeignKey("users.id", ondelete="CASCADE"), index=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("repository_url", sa.String(500), nullable=True),
        sa.Column("github_repo_id", sa.Integer, nullable=True),
        sa.Column("language", sa.String(50), default="python"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_scanned_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "scans",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("project_id", UUID(as_uuid=False), sa.ForeignKey("projects.id", ondelete="CASCADE"), index=True),
        sa.Column("scan_type", sa.String(50), default="manual"),
        sa.Column("status", sa.String(50), default="queued", index=True),
        sa.Column("commit_hash", sa.String(40), nullable=True),
        sa.Column("branch_name", sa.String(255), nullable=True),
        sa.Column("pr_number", sa.Integer, nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("total_files_scanned", sa.Integer, default=0),
        sa.Column("total_lines_scanned", sa.Integer, default=0),
        sa.Column("overall_risk_score", sa.Float, default=0.0),
        sa.Column("scan_duration_seconds", sa.Integer, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "vulnerabilities",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("scan_id", UUID(as_uuid=False), sa.ForeignKey("scans.id", ondelete="CASCADE"), index=True),
        sa.Column("file_path", sa.String(500), nullable=False),
        sa.Column("line_number", sa.Integer, nullable=False),
        sa.Column("end_line_number", sa.Integer, nullable=True),
        sa.Column("vulnerability_type", sa.String(100), nullable=False, index=True),
        sa.Column("severity", sa.String(20), nullable=False, index=True),
        sa.Column("cvss_score", sa.Float, default=0.0),
        sa.Column("confidence", sa.Float, default=0.5),
        sa.Column("code_snippet", sa.Text, nullable=False),
        sa.Column("vulnerable_code", sa.Text, nullable=False),
        sa.Column("ai_explanation", sa.Text, nullable=True),
        sa.Column("ai_fixed_code", sa.Text, nullable=True),
        sa.Column("remediation_steps", JSONB, nullable=True),
        sa.Column("cwe_id", sa.String(20), nullable=True),
        sa.Column("is_false_positive", sa.Boolean, default=False),
        sa.Column("false_positive_reason", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "reports",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("scan_id", UUID(as_uuid=False), sa.ForeignKey("scans.id", ondelete="CASCADE"), index=True),
        sa.Column("report_type", sa.String(20), default="pdf"),
        sa.Column("file_path", sa.String(500), nullable=False),
        sa.Column("file_size_bytes", sa.Integer, default=0),
        sa.Column("generated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "taint_flows",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("vulnerability_id", UUID(as_uuid=False), sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE")),
        sa.Column("source_file", sa.String(500), nullable=False),
        sa.Column("source_line", sa.Integer, nullable=False),
        sa.Column("source_type", sa.String(100), nullable=False),
        sa.Column("sink_file", sa.String(500), nullable=False),
        sa.Column("sink_line", sa.Integer, nullable=False),
        sa.Column("sink_type", sa.String(100), nullable=False),
        sa.Column("flow_path", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "scan_metrics",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("scan_id", UUID(as_uuid=False), sa.ForeignKey("scans.id", ondelete="CASCADE")),
        sa.Column("metric_name", sa.String(100), nullable=False),
        sa.Column("metric_value", sa.Float, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "cicd_integrations",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("project_id", UUID(as_uuid=False), sa.ForeignKey("projects.id", ondelete="CASCADE")),
        sa.Column("integration_type", sa.String(50), nullable=False),
        sa.Column("webhook_url", sa.String(500), nullable=False),
        sa.Column("secret_token", sa.String(255), nullable=False),
        sa.Column("block_on_critical", sa.Boolean, default=True),
        sa.Column("block_on_high", sa.Boolean, default=False),
        sa.Column("is_active", sa.Boolean, default=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("cicd_integrations")
    op.drop_table("scan_metrics")
    op.drop_table("taint_flows")
    op.drop_table("reports")
    op.drop_table("vulnerabilities")
    op.drop_table("scans")
    op.drop_table("projects")
    op.drop_table("users")