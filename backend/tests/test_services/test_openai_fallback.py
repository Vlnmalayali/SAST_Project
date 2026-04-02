import pytest

from app.ai.openai_client import explain_vulnerability, suggest_fix
from app.config import settings


@pytest.mark.asyncio
async def test_explain_vulnerability_uses_rule_fallback_when_ai_disabled(monkeypatch):
    monkeypatch.setattr(settings, "AI_ENABLED", False)
    monkeypatch.setattr(settings, "OPENAI_API_KEY", "")

    result = await explain_vulnerability(
        vulnerability_type="sql_injection",
        file_path="sample.py",
        line_number=10,
        code_snippet="cursor.execute(query)",
    )

    assert result is not None
    assert "explanation" in result
    assert result.get("cwe") == "CWE-89"


@pytest.mark.asyncio
async def test_suggest_fix_uses_rule_fallback_when_ai_disabled(monkeypatch):
    monkeypatch.setattr(settings, "AI_ENABLED", False)
    monkeypatch.setattr(settings, "OPENAI_API_KEY", "")

    result = await suggest_fix(
        vulnerability_type="xss",
        vulnerable_code="return f'<h1>{name}</h1>'",
        description="XSS risk",
    )

    assert result is not None
    assert isinstance(result.get("remediation_steps"), list)
