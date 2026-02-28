"""OpenAI API client with retry logic and error handling."""

import json
import logging
from typing import Any

import openai

from app.config import settings
from app.ai.prompts import (
    SYSTEM_PROMPT_EXPLANATION,
    SYSTEM_PROMPT_FIX,
    EXPLAIN_TEMPLATE,
    FIX_TEMPLATE,
)

logger = logging.getLogger(__name__)

client = openai.AsyncOpenAI(api_key=settings.OPENAI_API_KEY)


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

    return await _call_openai(SYSTEM_PROMPT_EXPLANATION, prompt)


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

    return await _call_openai(SYSTEM_PROMPT_FIX, prompt)


async def _call_openai(system_prompt: str, user_prompt: str) -> dict[str, Any] | None:
    """Make an OpenAI API call with retry and fallback."""
    if not settings.OPENAI_API_KEY or settings.OPENAI_API_KEY.startswith("sk-your"):
        logger.warning("OpenAI API key not configured, skipping AI analysis")
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
