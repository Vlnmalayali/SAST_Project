from app.core.compliance_mapping import OWASP_TOP10_VERSION, get_compliance_mapping


def test_sql_injection_compliance_mapping_owasp_2025():
    mapped = get_compliance_mapping("sql_injection", cwe_id="CWE-89")

    assert mapped["owasp_top10"] == "A05:2025 Injection"
    assert mapped["owasp_top10_2025"] == "A05:2025 Injection"
    assert mapped["cwe"] == "CWE-89"
    assert any("Requirement 6.2.4" in req for req in mapped["pci_dss"])
    assert "Article 32" in mapped["gdpr"]
    assert mapped["mapping_version"]["owasp_top10"] == OWASP_TOP10_VERSION


def test_hardcoded_secret_compliance_mapping():
    mapped = get_compliance_mapping("hardcoded_secret", cwe_id="CWE-798")
    assert mapped["owasp_top10"] == "A04:2025 Cryptographic Failures"
    assert mapped["cwe"] == "CWE-798"
    assert any("Requirement 8.6.2" in req for req in mapped["pci_dss"])
    assert "Article 32" in mapped["gdpr"]


def test_supply_chain_compliance_mapping():
    mapped = get_compliance_mapping("supply_chain_failure", cwe_id="CWE-1104")
    assert mapped["owasp_top10"] == "A03:2025 Software Supply Chain Failures"
    assert mapped["cwe"] == "CWE-1104"
    assert any("Requirement 6.3.3" in req for req in mapped["pci_dss"])


def test_exception_mishandling_compliance_mapping():
    mapped = get_compliance_mapping("exception_mishandling", cwe_id="CWE-755")
    assert mapped["owasp_top10"] == "A10:2025 Mishandling of Exceptional Conditions"
    assert mapped["cwe"] == "CWE-755"
    assert "Article 32" in mapped["gdpr"]


def test_unknown_mapping_defaults():
    mapped = get_compliance_mapping("unknown_type", cwe_id=None)
    assert mapped["owasp_top10"] is None
    assert mapped["mapping_version"]["owasp_top10"] == OWASP_TOP10_VERSION
