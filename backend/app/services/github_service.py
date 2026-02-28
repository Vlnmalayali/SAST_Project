"""GitHub integration service."""

import logging
import os
import shutil

import httpx
from github import Github

from app.config import settings

logger = logging.getLogger(__name__)


def get_oauth_url() -> str:
    return (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={settings.GITHUB_CLIENT_ID}"
        f"&scope=repo,write:discussion"
        f"&redirect_uri={settings.GITHUB_REDIRECT_URI}"
    )


async def exchange_code_for_token(code: str) -> str | None:
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://github.com/login/oauth/access_token",
            json={
                "client_id": settings.GITHUB_CLIENT_ID,
                "client_secret": settings.GITHUB_CLIENT_SECRET,
                "code": code,
            },
            headers={"Accept": "application/json"},
        )
        if response.status_code == 200:
            data = response.json()
            return data.get("access_token")
    return None


def list_repos(token: str) -> list[dict]:
    g = Github(token)
    repos = []
    for repo in g.get_user().get_repos(sort="updated"):
        repos.append(
            {
                "id": repo.id,
                "name": repo.name,
                "full_name": repo.full_name,
                "private": repo.private,
                "url": repo.html_url,
                "language": (repo.language or "unknown").lower(),
            }
        )
    return repos


def clone_repository(token: str, repo_full_name: str, dest_dir: str, branch: str = "main") -> str:
    """Clone a GitHub repository to a local directory."""
    clone_url = f"https://{token}@github.com/{repo_full_name}.git"
    repo_dir = os.path.join(dest_dir, repo_full_name.split("/")[-1])

    import git

    try:
        git.Repo.clone_from(clone_url, repo_dir, branch=branch, depth=1)
    except git.exc.GitCommandError:
        # Try default branch if specified branch fails
        git.Repo.clone_from(clone_url, repo_dir, depth=1)

    return repo_dir


def post_pr_comment(token: str, repo_full_name: str, pr_number: int, comment_body: str):
    """Post a comment on a GitHub pull request."""
    g = Github(token)
    repo = g.get_repo(repo_full_name)
    pr = repo.get_pull(pr_number)
    pr.create_issue_comment(comment_body)


def format_pr_comment(scan_data: dict) -> str:
    """Format scan results as a GitHub PR comment."""
    score = scan_data.get("overall_risk_score", 0)
    critical = scan_data.get("critical_count", 0)
    high = scan_data.get("high_count", 0)
    medium = scan_data.get("medium_count", 0)
    low = scan_data.get("low_count", 0)

    if score >= 8:
        label = "🔴 Critical Risk"
    elif score >= 6:
        label = "🟠 High Risk"
    elif score >= 4:
        label = "🟡 Medium Risk"
    else:
        label = "🟢 Low Risk"

    comment = f"""## 🔒 Security Scan Results

**Overall Risk Score:** {score}/10.0 — **{label}**

### Summary
| Severity | Count |
|----------|-------|
| 🔴 Critical | {critical} |
| 🟠 High | {high} |
| 🟡 Medium | {medium} |
| 🟢 Low | {low} |
"""

    if critical > 0 or high > 0:
        comment += "\n### ⚠️ Action Required\nThis PR introduces security vulnerabilities that should be addressed before merging.\n"

    comment += "\n---\n*Powered by AI-SAST*"
    return comment
