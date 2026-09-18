# Design Decisions

## Milestone 1: Compose networking, volumes, env vars

- **Networking**: no custom Docker network defined. Compose creates a default
  bridge network for the project and puts every service on it automatically;
  services reach each other by service name (e.g. `backend` connects to Neo4j
  at `bolt://neo4j:7687`, not `localhost`). A custom network isn't needed
  until we have a reason to isolate services from each other.
- **Volumes**: `neo4j_data` is a named volume mounted at `/data` in the
  `neo4j` container, so graph data survives `docker compose down` (but not
  `docker compose down -v`). The backend has no volume yet — no persistent
  state to keep, and no bind mount for live-reload since we're not there yet.
- **Env vars**: `NEO4J_USER`/`NEO4J_PASSWORD` live in a gitignored `.env`,
  with `.env.example` committed as the template. `docker compose` loads
  `.env` automatically from the compose file's directory.
- **Startup ordering**: `backend` uses `depends_on: neo4j: condition:
  service_healthy` (via a `wget`-based healthcheck) rather than a plain
  `depends_on`, since Neo4j takes a few seconds to accept Bolt connections
  after the container starts.
