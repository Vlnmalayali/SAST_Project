"""Celery tasks for GitHub integration."""

import logging
import os
import shutil

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.config import settings
from app.tasks import celery_app
from app.tasks.scan_tasks import run_scan_directory_task
from app.models.scan import Scan
from app.services.github_service import clone_repository, post_pr_comment, format_pr_comment

logger = logging.getLogger(__name__)
sync_engine = create_engine(settings.DATABASE_URL_SYNC, pool_pre_ping=True)


@celery_app.task(name="tasks.github_pr_scan")
def github_pr_scan_task(
    scan_id: str,
    github_token: str,
    repo_full_name: str,
    branch: str,
    pr_number: int | None = None,
    language: str = "python",
):
    """Clone a GitHub repo, scan it, and optionally comment on the PR."""
    scan_dir = os.path.join(settings.SCAN_STORAGE_PATH, scan_id)
    os.makedirs(scan_dir, exist_ok=True)

    try:
        # Clone repository
        repo_dir = clone_repository(github_token, repo_full_name, scan_dir, branch)
        logger.info(f"Cloned {repo_full_name}:{branch} to {repo_dir}")

        # Run the scan (this is synchronous within celery)
        run_scan_directory_task(scan_id, repo_dir, language)

        # Post PR comment if applicable
        if pr_number:
            _post_scan_results_to_pr(scan_id, github_token, repo_full_name, pr_number)

    except Exception as e:
        logger.error(f"GitHub PR scan failed for {scan_id}: {e}", exc_info=True)
        with Session(sync_engine) as db:
            scan = db.get(Scan, scan_id)
            if scan:
                scan.status = "failed"
                db.commit()
    finally:
        shutil.rmtree(scan_dir, ignore_errors=True)


def _post_scan_results_to_pr(scan_id: str, github_token: str, repo_full_name: str, pr_number: int):
    """Post scan results as a PR comment."""
    try:
        with Session(sync_engine) as db:
            scan = db.get(Scan, scan_id)
            if not scan or scan.status != "completed":
                return

            from sqlalchemy import func, select
            from app.models.vulnerability import Vulnerability

            result = db.execute(
                select(Vulnerability.severity, func.count(Vulnerability.id))
                .where(Vulnerability.scan_id == scan_id)
                .group_by(Vulnerability.severity)
            )
            counts = dict(result.all())

            scan_data = {
                "overall_risk_score": scan.overall_risk_score,
                "critical_count": counts.get("critical", 0),
                "high_count": counts.get("high", 0),
                "medium_count": counts.get("medium", 0),
                "low_count": counts.get("low", 0),
            }

            comment = format_pr_comment(scan_data)
            post_pr_comment(github_token, repo_full_name, pr_number, comment)
            logger.info(f"Posted PR comment on {repo_full_name}#{pr_number}")

    except Exception as e:
        logger.error(f"Failed to post PR comment: {e}")
