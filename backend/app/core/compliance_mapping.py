"""Compliance framework mappings for vulnerability findings (OWASP Top 10:2025 only)."""

from __future__ import annotations

from dataclasses import dataclass

OWASP_TOP10_VERSION = "2025"


@dataclass(frozen=True)
class ComplianceEntry:
    owasp_2025: str | None
    cwe: str | None
    pci_dss: list[str]
    gdpr: list[str]


_VULNERABILITY_COMPLIANCE_MAP: dict[str, ComplianceEntry] = {
    "sql_injection": ComplianceEntry(
        owasp_2025="A05:2025 Injection",
        cwe="CWE-89",
        pci_dss=[
            "Requirement 6.2.4 (secure coding against injection)",
            "Requirement 6.3.2 (code review and secure coding process)",
        ],
        gdpr=["Article 32"],
    ),
    "xss": ComplianceEntry(
        owasp_2025="A05:2025 Injection",
        cwe="CWE-79",
        pci_dss=["Requirement 6.2.4 (secure coding against injection)"],
        gdpr=["Article 32"],
    ),
    "command_injection": ComplianceEntry(
        owasp_2025="A05:2025 Injection",
        cwe="CWE-78",
        pci_dss=["Requirement 6.2.4 (secure coding against injection)"],
        gdpr=["Article 32"],
    ),
    "hardcoded_secret": ComplianceEntry(
        owasp_2025="A04:2025 Cryptographic Failures",
        cwe="CWE-798",
        pci_dss=[
            "Requirement 8.6.2 (no hard-coded credentials in code/config/scripts)",
            "Requirement 8.6.3 (protect and rotate application/system account secrets)",
        ],
        gdpr=["Article 32", "Article 5(1)(f)"],
    ),
    "weak_crypto": ComplianceEntry(
        owasp_2025="A04:2025 Cryptographic Failures",
        cwe="CWE-327",
        pci_dss=[
            "Requirement 3 (protect stored account data)",
            "Requirement 4 (protect data in transit)",
        ],
        gdpr=["Article 32"],
    ),
    "insecure_deserialization": ComplianceEntry(
        owasp_2025="A08:2025 Software or Data Integrity Failures",
        cwe="CWE-502",
        pci_dss=["Requirement 6.2.4 (secure coding techniques)"],
        gdpr=["Article 32"],
    ),
    "unsafe_eval": ComplianceEntry(
        owasp_2025="A05:2025 Injection",
        cwe="CWE-95",
        pci_dss=["Requirement 6.2.4 (secure coding techniques)"],
        gdpr=["Article 32"],
    ),
    "path_traversal": ComplianceEntry(
        owasp_2025="A01:2025 Broken Access Control",
        cwe="CWE-22",
        pci_dss=["Requirement 7 (restrict access by business need-to-know)"],
        gdpr=["Article 32"],
    ),
    "supply_chain_failure": ComplianceEntry(
        owasp_2025="A03:2025 Software Supply Chain Failures",
        cwe="CWE-1104",
        pci_dss=[
            "Requirement 6.3.3 (software integrity and trusted components)",
            "Requirement 11.3.1 (vulnerability identification in components)",
        ],
        gdpr=["Article 32"],
    ),
    "exception_mishandling": ComplianceEntry(
        owasp_2025="A10:2025 Mishandling of Exceptional Conditions",
        cwe="CWE-755",
        pci_dss=[
            "Requirement 6.2 (secure coding and error handling)",
            "Requirement 10.2 (security event logging and traceability)",
        ],
        gdpr=["Article 32", "Article 5(1)(f)"],
    ),
}

_CWE_FALLBACK_MAP: dict[str, ComplianceEntry] = {
    entry.cwe: entry for entry in _VULNERABILITY_COMPLIANCE_MAP.values() if entry.cwe
}


def get_compliance_mapping(vulnerability_type: str, cwe_id: str | None = None) -> dict:
    entry = _VULNERABILITY_COMPLIANCE_MAP.get(vulnerability_type)

    if entry is None and cwe_id:
        entry = _CWE_FALLBACK_MAP.get(cwe_id)

    if entry is None:
        return {
            "owasp_top10": None,
            "owasp_top10_2025": None,
            "cwe": cwe_id,
            "pci_dss": [],
            "gdpr": [],
            "mapping_version": {"owasp_top10": OWASP_TOP10_VERSION},
        }

    return {
        "owasp_top10": entry.owasp_2025,
        "owasp_top10_2025": entry.owasp_2025,
        "cwe": cwe_id or entry.cwe,
        "pci_dss": list(entry.pci_dss),
        "gdpr": list(entry.gdpr),
        "mapping_version": {"owasp_top10": OWASP_TOP10_VERSION},
    }
