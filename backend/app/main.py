"""FastAPI application entrypoint."""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from neo4j import GraphDatabase

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Create the Neo4j driver on startup, close it on shutdown
    """
    
    # Read environment variables 
    neo4j_uri = os.environ["NEO4J_URI"]
    neo4j_user = os.environ["NEO4J_USER"]
    neo4j_password = os.environ["NEO4J_PASSWORD"]
    
    # Create Neo4j driver
    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
    
    # Store driver in app.state
    app.state.neo4j_driver = driver
    
    yield
    
    #shutdown
    app.state.neo4j_driver.close()

app = FastAPI(
    title = "Threat Intelligence & Attack-Path Platform",
    lifespan=lifespan,
)

# Liveness check - this confirms the container itself is up.
@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/health/neo4j")
def health_neo4j(request: Request) -> dict[str, str]:
    """
    Readiness check - round-trips a real query to confirm 
    backend<->neo4j networking
    """
    
    # Route needs access to the application
    driver = request.app.state.neo4j_driver
    
    try:
        with driver.session() as session:
            result = session.run("RETURN 1 AS num")
            
            result.single()
        return{"status": "ok"}
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Neo4j unavailable"
        )
    
    
    