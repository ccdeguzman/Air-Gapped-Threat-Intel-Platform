"""
    Transform cached NVD JSON and load it into Neo4j as CVE nodes.

Split from fetch_nvd.py so the transform logic (the part worth unit testing)
doesn't depend on the network or a running Neo4j instance.
"""

import json
import os
from pathlib import Path

from dotenv import load_dotenv
from neo4j import GraphDatabase

DATA_DIR = Path(__file__).parent / "data"


def transform_cve(raw_cve: dict) -> dict:
    """Turn one NVD API 'cve' object into flat properties for a CVE node.
    
    Expected output keys:
        id
        description
        cvss_score
        severity
        cvss_version
        published

    CVSS policy:
        1. Prefer CVSS v3.1 -> Fall back to CVSS v3.0 -> Fall back to CVSS v2
        2. Within a version, prefer the Primary entry.
        3. If there is no Primary entry, use the first entry.
        4. If there is no CVSS data, score, severity and version are None.
        5. v3.x severity is read from cvssData; v2 severity is read from the
           entry itself (NVD puts it beside cvssData, not inside it).
        6. cvss_version records which scale the score and severity use, since
           v2 and v3 severity buckets differ.
    """
    # Pull CVE ID
    cve_id = raw_cve["id"]
      
    # Get english description
    description = None
    descriptions = raw_cve.get("descriptions", [])
    
    for item in descriptions:
        if item["lang"] == "en":
            description = item.get("value")
            break
        
    # Find best CVSS version
    cvss_score = None
    severity = None
    cvss_version = None
    
    metrics = raw_cve.get("metrics", {})
    
    cvss_ver = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
    
    for version in cvss_ver:
        # Does this version exist for this CVE
        if version not in metrics:
            continue
        
        entries = metrics[version]
        
        # Look for Primary CVSS entry
        selected = None
        
        for entry in entries:
            if entry.get("type") == "Primary":
                selected = entry
                break
        
        # If there is no primary, use the first entry
        if selected is None and entries:
            selected = entries[0]
        
        # Nothing usable
        if selected is None:
            continue
        
        # Extract CVSS data
        cvss_data = selected.get("cvssData", {})
        cvss_score = cvss_data.get("baseScore")
        cvss_version = cvss_data.get("version")
        
        # v3.x keeps baseSeverity inside cvssData; v2 keeps it on the entry.
        if version == "cvssMetricV2":
            severity = selected.get("baseSeverity")
        else:
            severity = cvss_data.get("baseSeverity")
        
        # Break once the highest-priority usable CVSS version is found
        break
    
    published = raw_cve.get("published")
    
    return {
        "id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "severity": severity,
        "cvss_version": cvss_version,
        "published": published,
    }


def ensure_constraint(driver) -> None:
    """
    Create the uniqueness constraint on CVE.id if it doesn't exist yet.
    It requires the id property of every CVE node to be unique
    """
    
    with driver.session() as session:
        session.run("""
                    CREATE CONSTRAINT cve_id_unique
                    IF NOT EXISTS FOR (c:CVE)
                    REQUIRE c.id IS UNIQUE
                    """)


def load_cve(tx, cve_props: dict) -> None:
    """
    Write a single transformed CVE via MERGE (idempotent re-runs).
    """
    
    query = """
    MERGE (c:CVE {id: $id})
    SET c.description = $description,
        c.cvss_score = $cvss_score,
        c.severity = $severity,
        c.cvss_version = $cvss_version,
        c.published = $published
    """
    
    tx.run(query, **cve_props)


def is_rejected(raw_cve: dict) -> bool:
    """True if NVD has withdrawn this CVE (vulnStatus == "Rejected")."""
    return raw_cve.get("vulnStatus") == "Rejected"


def delete_cve(tx, cve_id: str) -> None:
    """Remove a CVE node, and any relationships it has, if it exists."""
    tx.run("MATCH (c:CVE {id: $id}) DETACH DELETE c", id=cve_id)


def load_page(tx, cve_props_list: list[dict], rejected_ids: list[str]) -> None:
    """
    Apply one page in a single transaction: delete rejected CVEs, MERGE the rest.
    This is more efficient than writing each CVE in its own transaction.
    """
    for cve_id in rejected_ids:
        delete_cve(tx, cve_id)
    for cve_props in cve_props_list:
        load_cve(tx, cve_props)


def main() -> None:
    """Entry point: read cached JSON files from DATA_DIR, transform, load."""
    load_dotenv()
    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = os.environ.get("NEO4J_USER")
    password = os.environ.get("NEO4J_PASSWORD")
    if not user or not password:
        raise RuntimeError("NEO4J_USER and NEO4J_PASSWORD must be set - check your .env")

    page_files = sorted(DATA_DIR.glob("nvd_page_*.json"))
    if not page_files:
        raise RuntimeError(f"No cached pages in {DATA_DIR} - run fetch_nvd.py first")

    loaded = 0
    removed = 0
    with GraphDatabase.driver(uri, auth=(user, password)) as driver:
        ensure_constraint(driver)
        with driver.session() as session:
            for page_file in page_files:
                with open(page_file, "r", encoding="utf-8") as file:
                    page = json.load(file)
                raw_cves = [item["cve"] for item in page["vulnerabilities"]]
                rejected_ids = [c["id"] for c in raw_cves if is_rejected(c)]
                cve_props_list = [
                    transform_cve(c) for c in raw_cves if not is_rejected(c)
                ]
                session.execute_write(load_page, cve_props_list, rejected_ids)
                loaded += len(cve_props_list)
                removed += len(rejected_ids)
                print(f"{page_file.name}: {loaded} loaded, {removed} rejected removed so far")


if __name__ == "__main__":
    main()
