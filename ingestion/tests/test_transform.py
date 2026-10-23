"""
Unit tests for load_nvd.transform_cve.
"""

from ingestion.load_nvd import is_rejected, load_page, transform_cve


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


def test_is_rejected_true_for_rejected_status():
    assert is_rejected({"id": "CVE-TEST-0005", "vulnStatus": "Rejected"}) is True


def test_is_rejected_false_for_other_statuses():
    assert is_rejected({"id": "CVE-TEST-0006", "vulnStatus": "Analyzed"}) is False


def test_is_rejected_false_when_status_missing():
    assert is_rejected({"id": "CVE-TEST-0007"}) is False


class FakeTx:
    def __init__(self):
        self.calls = []

    def run(self, query, **params):
        self.calls.append((query.split()[0], params))


def test_load_page_deletes_rejected_and_merges_the_rest():
    tx = FakeTx()
    props = {"id": "CVE-TEST-0008", "description": "d", "cvss_score": None,
             "severity": None, "cvss_version": None, "published": "2020-01-01"}

    load_page(tx, [props], ["CVE-TEST-0009"])

    assert tx.calls == [("MATCH", {"id": "CVE-TEST-0009"}), ("MERGE", props)]