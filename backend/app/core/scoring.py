"""CVSS-style scoring engine for vulnerabilities."""

import math
from dataclasses import dataclass

ATTACK_VECTOR = {
    "network": 0.85,
    "adjacent": 0.62,
    "local": 0.55,
    "physical": 0.20,
}
ATTACK_COMPLEXITY = {"low": 0.77, "high": 0.44}
PRIVILEGES_REQUIRED = {"none": 0.85, "low": 0.62, "high": 0.27}
USER_INTERACTION = {"none": 0.85, "required": 0.62}
IMPACT_VALUES = {"high": 0.56, "low": 0.22, "none": 0.0}

VULN_TYPE_PROFILES = {
    "sql_injection": {
        "av": "network",
        "ac": "low",
        "pr": "none",
        "ui": "none",
        "c": "high",
        "i": "high",
        "a": "high",
    },
    "xss": {
        "av": "network",
        "ac": "low",
        "pr": "none",
        "ui": "required",
        "c": "low",
        "i": "low",
        "a": "none",
    },
    "command_injection": {
        "av": "network",
        "ac": "low",
        "pr": "none",
        "ui": "none",
        "c": "high",
        "i": "high",
        "a": "high",
    },
    "hardcoded_secret": {
        "av": "network",
        "ac": "low",
        "pr": "none",
        "ui": "none",
        "c": "high",
        "i": "none",
        "a": "none",
    },
    "weak_crypto": {
        "av": "network",
        "ac": "high",
        "pr": "none",
        "ui": "none",
        "c": "high",
        "i": "none",
        "a": "none",
    },
    "insecure_deserialization": {
        "av": "network",
        "ac": "low",
        "pr": "none",
        "ui": "none",
        "c": "high",
        "i": "high",
        "a": "high",
    },
    "unsafe_eval": {
        "av": "network",
        "ac": "low",
        "pr": "none",
        "ui": "none",
        "c": "high",
        "i": "high",
        "a": "high",
    },
    "path_traversal": {
        "av": "network",
        "ac": "low",
        "pr": "low",
        "ui": "none",
        "c": "high",
        "i": "low",
        "a": "none",
    },
}


@dataclass
class CVSSResult:
    base_score: float
    severity: str
    impact_subscore: float
    exploitability_subscore: float


def calculate_cvss(vulnerability_type: str, confidence: float = 1.0) -> CVSSResult:
    """Calculate CVSS-like score for a vulnerability type."""
    profile = VULN_TYPE_PROFILES.get(vulnerability_type)
    if not profile:
        return CVSSResult(
            base_score=5.0,
            severity="medium",
            impact_subscore=0.5,
            exploitability_subscore=0.5,
        )

    av = ATTACK_VECTOR[profile["av"]]
    ac = ATTACK_COMPLEXITY[profile["ac"]]
    pr = PRIVILEGES_REQUIRED[profile["pr"]]
    ui = USER_INTERACTION[profile["ui"]]

    c = IMPACT_VALUES[profile["c"]]
    i = IMPACT_VALUES[profile["i"]]
    a = IMPACT_VALUES[profile["a"]]

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    exploitability = 8.22 * av * ac * pr * ui

    if iss <= 0:
        base_score = 0.0
    else:
        base_score = min(10.0, round_up(iss * 6.42 + exploitability))

    base_score = round(base_score * confidence, 1)
    base_score = min(10.0, base_score)

    severity = score_to_severity(base_score)

    return CVSSResult(
        base_score=base_score,
        severity=severity,
        impact_subscore=round(iss, 2),
        exploitability_subscore=round(exploitability, 2),
    )


def score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    elif score >= 0.1:
        return "low"
    return "info"


def round_up(value: float) -> float:
    """Round up to one decimal place."""
    return math.ceil(value * 10) / 10


def calculate_project_risk_score(
    vulnerability_scores: list[dict],
) -> float:
    """Calculate aggregated project risk score."""
    if not vulnerability_scores:
        return 0.0

    severity_weights = {
        "critical": 4.0,
        "high": 2.0,
        "medium": 1.0,
        "low": 0.5,
        "info": 0.1,
    }

    weighted_sum = 0.0
    total_weight = 0.0
    critical_count = 0
    high_count = 0
    medium_count = 0

    for vuln in vulnerability_scores:
        severity = vuln.get("severity", "medium")
        score = vuln.get("cvss_score", 5.0)
        weight = severity_weights.get(severity, 1.0)

        weighted_sum += score * weight
        total_weight += weight

        if severity == "critical":
            critical_count += 1
        elif severity == "high":
            high_count += 1
        elif severity == "medium":
            medium_count += 1

    if total_weight == 0:
        return 0.0

    base = weighted_sum / total_weight

    penalty = 0.0
    if critical_count > 0:
        penalty += 2.0
    if high_count > 5:
        penalty += 1.0
    if medium_count > 20:
        penalty += 0.5

    return min(10.0, round(base + penalty, 1))
