"""CVSS v3.1 scoring engine for vulnerabilities."""

import math
from dataclasses import dataclass

METRIC_VALUES = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}

PR_VALUES_SCOPE_U = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_VALUES_SCOPE_C = {"N": 0.85, "L": 0.68, "H": 0.50}

VULN_TYPE_VECTORS = {
    "sql_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "xss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "command_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "hardcoded_secret": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "weak_crypto": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "insecure_deserialization": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "unsafe_eval": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "path_traversal": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
    "supply_chain_failure": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "exception_mishandling": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
}
DEFAULT_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"


@dataclass
class CVSSResult:
    base_score: float
    severity: str
    impact_subscore: float
    exploitability_subscore: float
    vector: str | None = None


def calculate_cvss(vulnerability_type: str, confidence: float = 1.0) -> CVSSResult:
    """
    Calculate CVSS v3.1 base score using official formula.

    Confidence is applied after CVSS computation as a project-specific weighting.
    """
    vector = VULN_TYPE_VECTORS.get(vulnerability_type, DEFAULT_VECTOR)
    parsed = _parse_vector(vector)

    # Fallback if vector is malformed.
    if not parsed:
        return CVSSResult(
            base_score=5.0,
            severity="medium",
            impact_subscore=0.5,
            exploitability_subscore=0.5,
            vector=vector,
        )

    scope = parsed["S"]
    av = METRIC_VALUES["AV"][parsed["AV"]]
    ac = METRIC_VALUES["AC"][parsed["AC"]]
    ui = METRIC_VALUES["UI"][parsed["UI"]]
    pr_map = PR_VALUES_SCOPE_C if scope == "C" else PR_VALUES_SCOPE_U
    pr = pr_map[parsed["PR"]]

    c = METRIC_VALUES["C"][parsed["C"]]
    i = METRIC_VALUES["I"][parsed["I"]]
    a = METRIC_VALUES["A"][parsed["A"]]

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    exploitability = 8.22 * av * ac * pr * ui

    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15)

    if impact <= 0:
        base_score = 0.0
    elif scope == "U":
        base_score = _round_up_1dp(min(impact + exploitability, 10.0))
    else:
        base_score = _round_up_1dp(min(1.08 * (impact + exploitability), 10.0))

    adjusted_score = min(10.0, round(base_score * _clamp(confidence, 0.0, 1.0), 1))
    severity = score_to_severity(adjusted_score)

    return CVSSResult(
        base_score=adjusted_score,
        severity=severity,
        impact_subscore=round(impact, 2),
        exploitability_subscore=round(exploitability, 2),
        vector=vector,
    )


def _parse_vector(vector: str) -> dict[str, str] | None:
    try:
        parts = vector.split("/")
        if not parts or not parts[0].startswith("CVSS:3.1"):
            return None
        metrics: dict[str, str] = {}
        for part in parts[1:]:
            key, value = part.split(":", 1)
            metrics[key] = value
        required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
        if not required.issubset(metrics):
            return None
        return metrics
    except Exception:
        return None


def score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 0.1:
        return "low"
    return "info"


def _round_up_1dp(value: float) -> float:
    return math.ceil(value * 10) / 10


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


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
