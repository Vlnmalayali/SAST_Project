from app.core.scoring import calculate_cvss


def test_cvss31_known_vector_scores():
    sqli = calculate_cvss("sql_injection", confidence=1.0)
    xss = calculate_cvss("xss", confidence=1.0)
    traversal = calculate_cvss("path_traversal", confidence=1.0)
    supply_chain = calculate_cvss("supply_chain_failure", confidence=1.0)
    exception = calculate_cvss("exception_mishandling", confidence=1.0)

    assert sqli.base_score == 9.8
    assert sqli.severity == "critical"
    assert xss.base_score == 6.1
    assert xss.severity == "medium"
    assert traversal.base_score == 7.1
    assert traversal.severity == "high"
    assert supply_chain.base_score == 8.8
    assert supply_chain.severity == "high"
    assert exception.base_score == 6.3
    assert exception.severity == "medium"


def test_cvss_confidence_adjustment():
    full = calculate_cvss("command_injection", confidence=1.0)
    reduced = calculate_cvss("command_injection", confidence=0.5)

    assert full.base_score == 9.8
    assert reduced.base_score == 4.9
    assert reduced.severity == "medium"
