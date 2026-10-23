"""
Fetch raw CVE data from the NVD API and cache it locally as JSON.

Deliberately separate from load_nvd.py: fetching is slow and rate-limited,
loading is fast and repeatable. Keeping the raw responses on disk means we
can re-run the load step against Neo4j without re-hitting the network.
"""

import os
import json
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000  # NVD's max per page
DATA_DIR = Path(__file__).parent / "data"
REQUEST_TIMEOUT = (10, 120)  # (connect, read) seconds

def fetch_page(start_index: int, results_per_page: int, api_key: str) -> dict:
    """
    Fetch a single page of CVEs from the NVD API.
    """
    params = {
        "startIndex": start_index,
        "resultsPerPage": results_per_page
    }
    headers = {
        "apiKey": api_key
    }
    # Request request.Response object
    response = requests.get(
        NVD_BASE_URL, params=params, headers=headers, timeout=REQUEST_TIMEOUT
    )
    
    # Making sure NVD returned a successful HTTP status
    response.raise_for_status()  # Raise an error for non-200 responses

    return response.json()  # Return the parsed JSON body


MAX_ATTEMPTS = 5
RETRYABLE_STATUS = {429, 500, 502, 503, 504}
TRANSIENT_ERRORS = (
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
    requests.exceptions.ChunkedEncodingError,
)


def fetch_page_with_retry(start_index: int, results_per_page: int, api_key: str) -> dict:
    """Call fetch_page, retrying transient failures with exponential backoff."""
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            return fetch_page(start_index, results_per_page, api_key)
        except requests.exceptions.HTTPError as err:
            if err.response.status_code not in RETRYABLE_STATUS:
                raise
            error = err
        except TRANSIENT_ERRORS as err:
            error = err

        if attempt == MAX_ATTEMPTS:
            raise error
        delay = 2 ** attempt
        print(f"Attempt {attempt} failed ({type(error).__name__}); retrying in {delay}s")
        time.sleep(delay)


def fetch_all(api_key: str) -> None:
    """
    Page through the full NVD CVE dataset and dump each page to DATA_DIR.
    """
    os.makedirs(DATA_DIR, exist_ok=True)
    
    start_index = 0
    page_number = 0
    total_results = None
    
    while total_results is None or start_index < total_results:
        filename = os.path.join(DATA_DIR, f"nvd_page_{page_number}.json")

        if os.path.exists(filename):
            # Already fetched - read totalResults from the cached page so a
            # fully-resumed run can still find the real stopping point
            # without an unnecessary live request.
            with open(filename, "r", encoding="utf-8") as file:
                cached_page = json.load(file)
            total_results = cached_page["totalResults"]
            print(f"Skipping page {page_number}, file already exists: {filename}")
        else:
            # Fetch one page 
            page = fetch_page_with_retry(start_index, RESULTS_PER_PAGE, api_key)
            # Get total number of results from the first page
            total_results = page["totalResults"]
            # Write to a temp file, then rename, so a page file is never half-written
            tmp_filename = f"{filename}.tmp"
            with open(tmp_filename, "w", encoding="utf-8") as file:
                json.dump(page, file)
            os.replace(tmp_filename, filename)
            print(f"Fetched page {page_number} ({start_index + RESULTS_PER_PAGE}/{total_results})")
            # Wait before next request to respect rate limit
            time.sleep(1)  # Adjust sleep time as needed based on rate limit
        # Advance to next page (regardless of whether we fetched or skipped)
        start_index += RESULTS_PER_PAGE
        page_number += 1

def main() -> None:
    """Entry point: load API key from env and fetch the full NVD dataset."""
    load_dotenv()
    api_key = os.environ.get("NVD_API_KEY")
    if not api_key:
        raise RuntimeError("NVD_API_KEY not set - check your .env")

    fetch_all(api_key)
    
if __name__ == "__main__":
    main()
