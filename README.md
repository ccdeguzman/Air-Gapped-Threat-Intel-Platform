# Air-Gapped Threat Intelligence & Attack Platform
Offline threat-intel platform: NVD CVEs, CISA KEV, MITRE ATT&CK & CWE in Neo4j, with Ollama + Qdrant mapping report text to attacker techniques.

## Developer
Christian de Guzman

## What It Does
- Ingests NVD CVEs, CISA KEV, MITRE ATT&CK, CWE into a graph (Neo4j)
- Imports nmap scans of your own lab, matches findings against the CVE graph
- Uses a local LLM (Ollama) to extract attacker behaviors from threat reports, embeds them (Qdrant), maps to ATT&CK techniques

## Tools and Technologies
Python, FastAPI, Neo4j, Qdrant, Ollama, Docker Compose