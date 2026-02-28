"""Parse and validate AI responses."""

import ast as python_ast
import logging
from typing import Any

logger = logging.getLogger(__name__)

VALID_CWE_PATTERN = r"^CWE-\d{1,5}$"


def parse_explanation(response: dict[str, Any] | None) -> dict[str, Any]:
    """Parse and validate an explanation response."""
    default = {
        "explanation": "AI explanation unavailable.",
        "exploitation": "",
        "impact": "",
        "cwe": None,
    }
    if not response:
        return default

    return {
        "explanation": _safe_str(response.get("explanation"), default["explanation"], 500),
        "exploitation": _safe_str(response.get("exploitation"), "", 300),
        "impact": _safe_str(response.get("impact"), "", 200),
        "cwe": _validate_cwe(response.get("cwe")),
    }


def parse_fix(response: dict[str, Any] | None) -> dict[str, Any]:
    """Parse and validate a fix suggestion response."""
    default = {
        "remediation_steps": [],
        "fixed_code": None,
        "fix_explanation": "",
    }
    if not response:
        return default

    fixed_code = response.get("fixed_code")
    if fixed_code and not _is_valid_python(fixed_code):
        logger.warning("AI-generated fix is not valid Python, discarding")
        fixed_code = None

    steps = response.get("remediation_steps", [])
    if not isinstance(steps, list):
        steps = [str(steps)]

    return {
        "remediation_steps": steps[:5],
        "fixed_code": fixed_code,
        "fix_explanation": _safe_str(response.get("fix_explanation"), "", 300),
    }


def _safe_str(value: Any, default: str, max_len: int = 500) -> str:
    if not value:
        return default
    return str(value)[:max_len]


def _validate_cwe(cwe: Any) -> str | None:
    import re

    if not cwe or not isinstance(cwe, str):
        return None
    if re.match(VALID_CWE_PATTERN, cwe):
        return cwe
    return None


def _is_valid_python(code: str) -> bool:
    """Check if code is syntactically valid Python."""
    try:
        python_ast.parse(code)
        return True
    except SyntaxError:
        return False
