# Design Decisions

## Milestone 1: Compose networking, volumes, env vars

- **Networking**: no custom Docker network defined. Compose creates a default
  bridge network for the project and puts every service on it automatically; services reach each other by service name (e.g. `backend` connects to Neo4j at `bolt://neo4j:7687`, not `localhost`). A custom network isn't needed until we have a reason to isolate services from each other.
- **Volumes**: `neo4j_data` is a named volume mounted at `/data` in the
  `neo4j` container, so graph data survives `docker compose down` (but not `docker compose down -v`). The backend has no volume yet — no persistent state to keep, and no bind mount for live-reload since we're not there yet.
- **Env vars**: `NEO4J_USER`/`NEO4J_PASSWORD` live in a gitignored `.env`, with `.env.example` committed as the template. `docker compose` loads `.env` automatically from the compose file's directory.
- **Startup ordering**: `backend` uses `depends_on: neo4j: condition: service_healthy` (via a `wget`-based healthcheck) rather than a plain `depends_on`, since Neo4j takes a few seconds to accept Bolt connections after the container starts.
- **v2 severity and `cvss_version`**: v3.x puts `baseSeverity` inside `cvssData`; v2 puts it on the metric entry itself, beside `cvssData`. We first decided not to store v2 severity, based on the wrong assumption that v2 had none. Running `transform_cve` over the first 2,000 real CVEs showed 1,929 were v2-only, so that would have dropped severity for most older CVEs. Now v2 severity is stored too. The two scales differ (v2 has LOW/MEDIUM/HIGH; v3 adds CRITICAL and narrows HIGH to 7.0-8.9), so each node also stores `cvss_version` (`"3.1"`, `"3.0"`, `"2.0"`) and a `severity` value is only comparable within one version.
- **No score available**: some CVEs (e.g. newly published, "awaiting analysis") have no `metrics` at all. `cvss_score`, `severity` and `cvss_version` are left as `None` rather than a sentinel value. In Neo4j  `SET x = null` removes the property, and Cypher treats a missing property and an explicit `null` the same way under both comparisons (`WHERE c.cvss_score > 7.0`) and `IS NULL` checks, so no sentinel is needed. 34 of the first 2,000 CVEs had no score.

## Done
- Milestone 2 (in progress): NVD CVE ingestion
  - Got and activated an NVD API key. An unconfirmed key returns 404 for any `apiKey` header, even a fake one; clicking the email confirmation fixed it.
  - `ingestion/` (sibling of `backend/`): `fetch_nvd.py` (paging, per-page JSON cache, skip-if-cached resume, 1 s pacing, timeout + retry with backoff) and `load_nvd.py` (`transform_cve`, uniqueness constraint,`MERGE` loader, one transaction per page). Run as `python -m ingestion.fetch_nvd` / `python -m ingestion.load_nvd` from `air_gapped_intelligence/`.
  - CVSS policy: v3.1 > v3.0 > v2, `Primary` over `Secondary`, store `cvss_version`, `None` when unscored. Corrected my assumption that v2 has no severity (it sits beside `cvssData`): 1,929 of the first 2,000 CVEs are v2-only.
  - pytest: 7 passing (4 transform, 3 retry, using `monkeypatch`).
  - Verified on page 0 in Neo4j Browser: 2,000 nodes, a re-load leaves the count unchanged, the constraint rejects a duplicate id, version and severity counts match the Python summary.
  - Debugged: a stray `raise NotImplementedError` left behind (three times), fields read from the wrong nesting level, an infinite loop caused by counters inside the `else`, code pasted into the wrong file, and a wrong auto-import (`zipfile.Path`).

## Milestone 2: NVD ingestion pipeline

- **API plus local cache**: we page through the NVD CVE API 2.0 and cache the raw JSON on disk, instead of using NVD's legacy bulk feed files.
  *Open item: confirm on NVD's site whether the legacy feeds are deprecated before stating that as the reason.*
- **Fetch and load are separate standalone scripts**: fetching is slow and rate-limited; loading is fast and repeatable. With the cache between them we can re-run the load without touching the network, and `transform_cve` is testable without a network or database. Ingestion is a batch job, so it lives in `ingestion/`, outside the always-running API container.
- **One file per page, skip-if-cached**: pages are saved as `nvd_page_<n>.json`. A re-run skips pages already on disk and reads `totalResults` from a cached page to find the stopping point, so a crash costs no completed work or rate-limit budget. The filenames depend on
- **Atomic page writes**: each page is written to `nvd_page_<n>.json.tmp` and then moved into place with `os.replace`. A rename is all-or-nothing, so a page file is either complete or absent. Without it, a fetch killed mid-write would leave a truncated file that the skip-if-cached check treats as "done" forever, and a loader running alongside the fetch could read a half-written file. Leftover `.tmp` files are harmless: the loader's `nvd_page_*.json` pattern ignores them and the next run overwrites them. Checked by simulating a crash mid-write: the real file never appeared.
  `RESULTS_PER_PAGE`: if it changes, clear the cache first (a mismatch
  causes overlapping pages, not gaps, and `MERGE` absorbs the overlap).
- **Pacing**: the key allows 50 requests per 30 seconds, a hard minimum spacing of 0.6 s. We sleep 1 s after each fetched page, about 40% margin, without noticeably lengthening the run.
- **Timeouts and retries**: `requests.get` has no default timeout, so `fetch_page` uses (10 s connect, 120 s read). In practice NVD cut off large responses mid-transfer (`ChunkedEncodingError`), so `fetch_page_with_retry` retries connection errors, timeouts, and HTTP 429/5xx with exponential backoff (2, 4, 8, 16 s; 5 attempts) and then raises. It does not retry other 4xx errors: a 404 meant the key wasn't activated, and retrying that only wastes time. `fetch_page` stays a pure single-request function; the retry policy is a separate wrapper.
- **Paths**: `DATA_DIR` is anchored to the script file (`__file__`), not the working directory, so scripts behave the same wherever they're launched.
- **Neo4j address**: scripts run on the host and use `bolt://localhost:7687` (the published port), overridable with `NEO4J_URI`. The backend container uses `bolt://neo4j:7687`; that name only resolves inside the Compose network.
- **Graph model (CVE only for now)**: `CVE {id, description, cvss_score, severity, cvss_version, published}`. CWE relationships are deferred to a later milestone.
- **Idempotent loading**: `MERGE (c:CVE {id: $id})` matches on `id` only, then `SET` updates every other property. Matching on all properties would\turn a revised description or score into a second node. A uniqueness constraint (created with `IF NOT EXISTS`) enforces it and gives `MERGE` an\index to seek on, avoiding a full label scan for each of ~400k lookups (roughly O(n log n) instead of O(n²) overall).
- **One transaction per page**: `load_page` writes a page of up to 2,000
  CVEs in one transaction, about 200 commits instead of ~400k. If a page
  fails, only it rolls back, and the re-run is safe because of `MERGE`.
  Batching with `UNWIND` would be faster still; deferred as an optimization.

## Next
- Milestone 2, remaining:
  1. Finish the fetch: 55 of ~200 pages cached (through mid-2018); newer CVEs are missing. Re-run `python -m ingestion.fetch_nvd` to resume. NVD dropped several large responses; if retries stay frequent, try `RESULTS_PER_PAGE = 1000` (clear the cache first).
  2. Make the page write atomic (temp file + `os.replace`) and add a per-page progress print.
  3. Run the full load; check the Neo4j count is near NVD's `totalResults` (398,697 on 2026-10-22) and note the load time.
  4. Add the atomic-write bullet to `docs/DESIGN_DECISIONS.md`; confirm whether NVD's legacy feeds are deprecated.
  5. Commit the Milestone 2 code (nothing is committed yet).
  6. Milestone wrap-up: what I learned, 2-3 interview questions, a draft resume bullet.

## Open issues / notes
- **Timeline**: the end-of-October target is at risk after a ~4-week
  break and Milestones 3-6 still ahead. Decide what to cut (CWE layer,
  multi-hop paths, UI) once Milestone 2 closes.
- **Fetch reliability**: NVD drops large responses (`ChunkedEncodingError`).
  Cached filenames depend on `RESULTS_PER_PAGE`; changing it means clearing `ingestion/data/`. `fetch_all` also re-parses every cached file in the skip branch, though it only needs the first page's `totalResults`.
- **Disk**: 16 GB free on C:. The full cache is ~1-2.5 GB; Ollama models in Milestone 6 need several GB.
- **Restarting a session**: use `.venv\Scripts\python.exe` directly (the
  venv is 3.10.11; system `python` is 3.14), start Docker Desktop, then
  `docker compose up -d`.