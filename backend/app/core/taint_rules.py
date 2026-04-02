"""Language-specific taint rule loading utilities."""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

SUPPORTED_TAINT_LANGUAGES = {"python", "javascript", "java"}

_LANGUAGE_ALIASES = {
    "py": "python",
    "python3": "python",
    "js": "javascript",
    "ts": "javascript",
    "node": "javascript",
}


@dataclass(frozen=True)
class TaintRules:
    sources: set[str]
    sinks: dict[str, str]
    sanitizers: set[str]


def normalize_taint_language(language: str | None) -> str:
    normalized = (language or "python").strip().lower()
    normalized = _LANGUAGE_ALIASES.get(normalized, normalized)
    if normalized not in SUPPORTED_TAINT_LANGUAGES:
        return "python"
    return normalized


@lru_cache(maxsize=8)
def load_taint_rules(language: str | None = "python") -> TaintRules:
    normalized = normalize_taint_language(language)
    rules_path = Path(__file__).with_name("taint_rules") / f"{normalized}.json"

    try:
        raw = json.loads(rules_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        if normalized != "python":
            return load_taint_rules("python")
        return TaintRules(sources=set(), sinks={}, sanitizers=set())

    return TaintRules(
        sources=set(raw.get("sources", [])),
        sinks=dict(raw.get("sinks", {})),
        sanitizers=set(raw.get("sanitizers", [])),
    )
