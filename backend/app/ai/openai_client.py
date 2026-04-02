"""OpenAI API client with retry logic and rule-based fallback support."""

import json
import logging
from typing import Any

import openai

from app.ai.prompts import (
    EXPLAIN_TEMPLATE,
    FIX_TEMPLATE,
    SYSTEM_PROMPT_EXPLANATION,
    SYSTEM_PROMPT_FIX,
)
from app.config import settings

logger = logging.getLogger(__name__)

client = openai.AsyncOpenAI(api_key=settings.OPENAI_API_KEY)

RULE_BASED_EXPLANATIONS = {
    "sql_injection": {
        "explanation": "User input appears to flow into a SQL query without safe parameterization.",
        "exploitation": "Attackers can inject SQL fragments to access or modify unintended records.",
        "impact": "Compromised data confidentiality and integrity.",
        "cwe": "CWE-89",
    },
    "xss": {
        "explanation": "Untrusted input appears to be rendered in HTML output without escaping.",
        "exploitation": "Attackers can inject script payloads that execute in user browsers.",
        "impact": "Session theft, phishing, and account takeover risk.",
        "cwe": "CWE-79",
    },
    "command_injection": {
        "explanation": "Untrusted input appears to be used in shell or command execution.",
        "exploitation": "Attackers can execute arbitrary OS commands on the host.",
        "impact": "Potential remote code execution and system compromise.",
        "cwe": "CWE-78",
    },
    "hardcoded_secret": {
        "explanation": "Credential-like material appears hardcoded in source code.",
        "exploitation": "Secrets may leak from source control, logs, or artifacts.",
        "impact": "Unauthorized access to protected resources.",
        "cwe": "CWE-798",
    },
    "weak_crypto": {
        "explanation": "A weak cryptographic primitive or unsafe crypto usage was detected.",
        "exploitation": "Attackers may break protections faster than intended.",
        "impact": "Loss of confidentiality and integrity guarantees.",
        "cwe": "CWE-327",
    },
    "insecure_deserialization": {
        "explanation": "Potentially unsafe deserialization of untrusted input is present.",
        "exploitation": "Attackers may trigger gadget chains for code execution.",
        "impact": "Code execution, data tampering, or denial of service.",
        "cwe": "CWE-502",
    },
    "unsafe_eval": {
        "explanation": "Dynamic code evaluation is used with potentially untrusted input.",
        "exploitation": "Attackers can execute arbitrary code in application context.",
        "impact": "Remote code execution and broad compromise risk.",
        "cwe": "CWE-95",
    },
    "path_traversal": {
        "explanation": "File paths built from user-controlled data may allow traversal sequences.",
        "exploitation": "Attackers may read or overwrite files outside intended directories.",
        "impact": "Exposure of sensitive files and privilege abuse.",
        "cwe": "CWE-22",
    },
    "supply_chain_failure": {
        "explanation": "Project dependencies or build behavior indicate a potential software supply-chain risk.",
        "exploitation": "Attackers may abuse typosquatted or malicious packages to execute untrusted code.",
        "impact": "Compromised build pipeline and broad downstream code execution risk.",
        "cwe": "CWE-1104",
    },
    "exception_mishandling": {
        "explanation": "Exception handling appears to suppress errors or leak sensitive runtime details.",
        "exploitation": "Attackers may trigger fail-open logic or harvest internal implementation details.",
        "impact": "Bypassed protections, data disclosure, and reduced incident visibility.",
        "cwe": "CWE-755",
    },
}

RULE_BASED_FIXES = {
    "sql_injection": {
        "remediation_steps": [
            "Use parameterized queries or prepared statements.",
            "Never concatenate raw user input into SQL strings.",
            "Validate expected input formats before query execution.",
        ],
        "fixed_code": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        "fix_explanation": "Parameterized SQL separates query logic from user-supplied data.",
    },
    "xss": {
        "remediation_steps": [
            "Escape untrusted values before rendering in HTML.",
            "Use template engines with auto-escaping enabled.",
            "Use a sanitizer for rich text input.",
        ],
        "fixed_code": "safe_name = html.escape(name)\nreturn f'<h1>{safe_name}</h1>'",
        "fix_explanation": "Escaping prevents browser execution of injected markup/scripts.",
    },
    "command_injection": {
        "remediation_steps": [
            "Avoid shell=True where possible.",
            "Pass command arguments as a list to subprocess APIs.",
            "Allowlist and validate command input.",
        ],
        "fixed_code": "subprocess.run(['ls', '--', safe_path], check=True, shell=False)",
        "fix_explanation": "Explicit argv usage blocks shell metacharacter injection.",
    },
    "hardcoded_secret": {
        "remediation_steps": [
            "Move secrets to environment variables or a secret manager.",
            "Rotate exposed credentials immediately.",
            "Add secret scanning in CI.",
        ],
        "fixed_code": "api_key = os.getenv('API_KEY')",
        "fix_explanation": "Externalized secrets reduce source exposure risk.",
    },
    "weak_crypto": {
        "remediation_steps": [
            "Replace weak algorithms with modern alternatives.",
            "Use approved library defaults and key sizes.",
            "Review hashing and salting strategy.",
        ],
        "fixed_code": "digest = hashlib.sha256(data).hexdigest()",
        "fix_explanation": "Modern cryptographic primitives improve resistance to attacks.",
    },
    "insecure_deserialization": {
        "remediation_steps": [
            "Avoid unsafe deserialization of untrusted data.",
            "Use safe parsers with strict schemas.",
            "Validate and authenticate serialized payloads.",
        ],
        "fixed_code": "data = json.loads(payload)",
        "fix_explanation": "Safe serialization formats reduce code execution gadget risks.",
    },
    "unsafe_eval": {
        "remediation_steps": [
            "Remove eval/exec usage for untrusted input.",
            "Use constrained parsers instead of dynamic execution.",
            "Allowlist accepted expression patterns.",
        ],
        "fixed_code": "value = ast.literal_eval(user_input)",
        "fix_explanation": "Literal parsing avoids arbitrary code execution.",
    },
    "path_traversal": {
        "remediation_steps": [
            "Normalize paths and enforce a trusted base directory.",
            "Reject traversal tokens and absolute paths.",
            "Use safe path-join helpers.",
        ],
        "fixed_code": "safe_path = os.path.normpath(os.path.join(BASE_DIR, filename))",
        "fix_explanation": "Path normalization with base checks prevents directory escape.",
    },
    "supply_chain_failure": {
        "remediation_steps": [
            "Pin all dependency versions and review update changes before release.",
            "Remove suspicious/typosquatted dependencies and verify package provenance.",
            "Avoid dynamic package installation during runtime and harden build scripts.",
        ],
        "fixed_code": "requests==2.32.3",
        "fix_explanation": "Pinned, trusted dependencies reduce unintended supply-chain drift.",
    },
    "exception_mishandling": {
        "remediation_steps": [
            "Replace bare/silent exception handlers with explicit exception classes and secure defaults.",
            "Avoid returning raw exception details to users; log them safely server-side.",
            "Ensure failure paths deny access instead of allowing operations by default.",
        ],
        "fixed_code": "except ValueError as exc:\n    logger.warning('Validation failed: %s', exc)\n    return {'error': 'Invalid input'}",
        "fix_explanation": "Explicit handling preserves observability without leaking sensitive internals.",
    },
}


def _is_ai_enabled() -> bool:
    return bool(
        settings.AI_ENABLED
        and settings.OPENAI_API_KEY
        and not settings.OPENAI_API_KEY.startswith("sk-your")
    )


def _fallback_explanation(vulnerability_type: str) -> dict[str, Any]:
    return RULE_BASED_EXPLANATIONS.get(
        vulnerability_type,
        {
            "explanation": "Automated explanation unavailable. Manual security review recommended.",
            "exploitation": "",
            "impact": "",
            "cwe": None,
        },
    )


def _fallback_fix(vulnerability_type: str) -> dict[str, Any]:
    return RULE_BASED_FIXES.get(
        vulnerability_type,
        {
            "remediation_steps": [
                "Validate and sanitize untrusted input.",
                "Use safer APIs and avoid dynamic execution patterns.",
                "Add tests for vulnerable and safe variants.",
            ],
            "fixed_code": None,
            "fix_explanation": "Apply secure-by-default coding patterns for this vulnerability type.",
        },
    )


async def explain_vulnerability(
    vulnerability_type: str,
    file_path: str,
    line_number: int,
    code_snippet: str,
) -> dict[str, Any] | None:
    """Get AI explanation for a vulnerability."""
    prompt = EXPLAIN_TEMPLATE.format(
        vulnerability_type=vulnerability_type,
        file_path=file_path,
        line_number=line_number,
        code_snippet=code_snippet[:2000],
    )

    if not _is_ai_enabled():
        logger.info("AI disabled or key missing, using rule-based explanation fallback")
        return _fallback_explanation(vulnerability_type)

    response = await _call_openai(SYSTEM_PROMPT_EXPLANATION, prompt)
    return response or _fallback_explanation(vulnerability_type)


async def suggest_fix(
    vulnerability_type: str,
    vulnerable_code: str,
    description: str,
) -> dict[str, Any] | None:
    """Get AI-suggested fix for a vulnerability."""
    prompt = FIX_TEMPLATE.format(
        vulnerability_type=vulnerability_type,
        vulnerable_code=vulnerable_code[:2000],
        description=description[:500],
    )

    if not _is_ai_enabled():
        logger.info("AI disabled or key missing, using rule-based fix fallback")
        return _fallback_fix(vulnerability_type)

    response = await _call_openai(SYSTEM_PROMPT_FIX, prompt)
    return response or _fallback_fix(vulnerability_type)


async def _call_openai(system_prompt: str, user_prompt: str) -> dict[str, Any] | None:
    """Make an OpenAI API call with retry and fallback."""
    if not _is_ai_enabled():
        logger.warning("AI disabled or OpenAI key not configured, skipping API call")
        return None

    models = [settings.OPENAI_MODEL, settings.OPENAI_FALLBACK_MODEL]

    for model in models:
        for attempt in range(3):
            try:
                response = await client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    max_tokens=settings.OPENAI_MAX_TOKENS,
                    temperature=0.3,
                    response_format={"type": "json_object"},
                )

                content = response.choices[0].message.content
                if content:
                    return json.loads(content)

            except openai.RateLimitError:
                import asyncio

                wait = 2 ** (attempt + 1)
                logger.warning(f"Rate limited, waiting {wait}s (attempt {attempt + 1})")
                await asyncio.sleep(wait)
            except openai.APIError as e:
                logger.error(f"OpenAI API error: {e}")
                break
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON from OpenAI (attempt {attempt + 1})")
                continue
            except Exception as e:
                logger.error(f"Unexpected error calling OpenAI: {e}")
                break

    return None
