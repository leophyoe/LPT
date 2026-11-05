"""Unit tests for CPENT methodology curriculum."""

from labs.cpent.curriculum import (
    get_all_cpent_tests,
    get_tests_by_methodology,
)


def test_cpent_curriculum_loads_all_tests():
    all_tests = get_all_cpent_tests()
    assert len(all_tests) > 10

    test_ids = [t.test_id for t in all_tests]
    assert "NET-1.1" in test_ids
    assert "NET-1.5" in test_ids
    assert "OSINT-1.1" in test_ids
    assert "SE-1.2" in test_ids


def test_cpent_filtering_by_methodology():
    net_tests = get_tests_by_methodology("Network Pentest")
    assert len(net_tests) > 0
    assert all(t.methodology == "Network Pentest" for t in net_tests)

    osint_tests = get_tests_by_methodology("OSINT")
    assert len(osint_tests) > 0
    assert all(t.methodology == "OSINT" for t in osint_tests)

    se_tests = get_tests_by_methodology("Social Engineering")
    assert len(se_tests) > 0
    assert all(t.methodology == "Social Engineering" for t in se_tests)

    # Test all other CPENT methodologies
    domains = [
        "Perimeter Devices",
        "Web Application Pentest",
        "Wireless Pentest",
        "IoT Pentest",
        "OT and SCADA Pentest",
        "Cloud Pentest",
        "Binary Analysis",
    ]
    for domain in domains:
        domain_tests = get_tests_by_methodology(domain)
        assert len(domain_tests) > 0, f"Expected tests for domain {domain}"
        assert all(domain.lower() in t.methodology.lower() for t in domain_tests)
