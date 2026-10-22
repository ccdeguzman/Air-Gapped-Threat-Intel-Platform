import pytest
import requests

from ingestion import fetch_nvd


def make_http_error(status):
    response = requests.Response()
    response.status_code = status
    return requests.exceptions.HTTPError(response=response)


def test_retry_recovers_from_transient_error(monkeypatch):
    calls = []

    def flaky(start_index, results_per_page, api_key):
        calls.append(1)
        if len(calls) < 3:
            raise requests.exceptions.ChunkedEncodingError("cut off")
        return {"totalResults": 1}

    monkeypatch.setattr(fetch_nvd, "fetch_page", flaky)
    monkeypatch.setattr(fetch_nvd.time, "sleep", lambda seconds: None)

    assert fetch_nvd.fetch_page_with_retry(0, 2000, "key") == {"totalResults": 1}
    assert len(calls) == 3


def test_retry_does_not_retry_404(monkeypatch):
    calls = []

    def not_found(start_index, results_per_page, api_key):
        calls.append(1)
        raise make_http_error(404)

    monkeypatch.setattr(fetch_nvd, "fetch_page", not_found)
    monkeypatch.setattr(fetch_nvd.time, "sleep", lambda seconds: None)

    with pytest.raises(requests.exceptions.HTTPError):
        fetch_nvd.fetch_page_with_retry(0, 2000, "key")
    assert len(calls) == 1


def test_retry_gives_up_after_max_attempts(monkeypatch):
    calls = []

    def always_503(start_index, results_per_page, api_key):
        calls.append(1)
        raise make_http_error(503)

    monkeypatch.setattr(fetch_nvd, "fetch_page", always_503)
    monkeypatch.setattr(fetch_nvd.time, "sleep", lambda seconds: None)

    with pytest.raises(requests.exceptions.HTTPError):
        fetch_nvd.fetch_page_with_retry(0, 2000, "key")
    assert len(calls) == fetch_nvd.MAX_ATTEMPTS