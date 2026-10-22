"""
Unit tests for load_nvd.transform_cve.
"""

from ingestion.load_nvd import transform_cve


def test_transform_cve_with_cvss_v31_score():
    """A CVE with a v3.1 CVSS score should map to cvss_score/severity."""
    metrics = {"cvssMetricV31": [{"type": "Primary", "source": "nvd@nist.gov", 
                                  "cvssData": {"version":  "3.1",
                                               "baseScore":  10.0,
                                               "baseSeverity":  "CRITICAL"}}]}
    raw_cve = {
        "id": "CVE-TEST-0001",
        "descriptions": [{"lang": "en", "value": "test description"}],
        "metrics": metrics,
        "published": "2021-12-10T10:15:00.000",
    }
    
    transform = transform_cve(raw_cve)
    
    assert transform["cvss_score"] == 10.0
    assert transform["severity"] == "CRITICAL"
    assert transform["cvss_version"] == "3.1"


def test_transform_cve_with_no_cvss_score():
    """A CVE with no CVSS score at all (e.g. very new/reserved) shouldn't crash -
    cvss_score/severity be instead should be None"""
    metrics = {}
    
    raw_cve = {
        "id": "CVE-TEST-0002",
        "descriptions": [{"lang": "en", "value": "test description"}],
        "metrics": metrics,
        "published": "2021-12-10T10:15:00.000",
    }
    
    transform = transform_cve(raw_cve)
    
    assert transform["cvss_score"] is None
    assert transform["severity"] is None
    assert transform["cvss_version"] is None
        

def test_transform_cve_with_multiple_cvss_versions():
    """A CVE scored under both v2 and v3.1 - confirm your policy picks the
    version you intended (probably prefer the highest CVSS version available)."""
    metrics = {"cvssMetricV31": [{"type": "Primary", "source": "nvd@nist.gov", 
                                  "cvssData": {"version":  "3.1",
                                               "baseScore":  9.8,
                                               "baseSeverity":  "CRITICAL"}}],
                "cvssMetricV2": [{"type": "Primary", "source": "nvd@nist.gov",
                                 "cvssData": {"version": "2.0",
                                              "baseScore": 7.5},
                                 "baseSeverity": "HIGH"}]}
    raw_cve = {
        "id": "CVE-TEST-0003",
        "descriptions": [{"lang": "en", "value": "test description"}],
        "metrics": metrics,
        "published": "2021-12-10T10:15:00.000",
    }
    transform = transform_cve(raw_cve)

    assert transform["cvss_score"] == 9.8
    assert transform["severity"] == "CRITICAL"
    assert transform["cvss_version"] == "3.1"


def test_transform_cve_with_cvss_v2_only():
    """A v2-only CVE (older CVEs) should store the entry-level baseSeverity."""
    metrics = {"cvssMetricV2": [{"type": "Primary", "source": "nvd@nist.gov",
                                 "cvssData": {"version": "2.0",
                                              "baseScore": 10.0},
                                 "baseSeverity": "HIGH"}]}
    raw_cve = {
        "id": "CVE-TEST-0004",
        "descriptions": [{"lang": "en", "value": "test description"}],
        "metrics": metrics,
        "published": "1988-10-01T04:00:00.000",
    }

    transform = transform_cve(raw_cve)

    assert transform["cvss_score"] == 10.0
    assert transform["severity"] == "HIGH"
    assert transform["cvss_version"] == "2.0"