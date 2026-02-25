"""FastAPI service — Ability Generation endpoint.

Exposes the two-phase reasoning engine via a single POST endpoint.
Starts the server with:

    uvicorn src.api.main:app --reload --port 8000

Or:

    python -m src.api.main
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from src.config import AGENT_VERSION, get_settings
from src.graph.connection import Neo4jConnection
from src.layers.layer2_enrichment import GalaxyManager
from src.layers.layer3_reasoning import ReasoningEngine
from src.llm import create_llm_client
from src.models.enums import AttackCategory, Platform

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────
# Request / Response schemas
# ──────────────────────────────────────────────────────────────


class GenerateRequest(BaseModel):
    """POST body for /generate."""

    category: AttackCategory = Field(
        ...,
        description="Attack category (maps to MITRE ATT&CK tactic).",
        examples=["credential_access"],
    )
    platform: Platform = Field(
        ...,
        description="Target platform.",
        examples=["windows"],
    )
    count: int = Field(
        default=1,
        ge=1,
        le=10,
        description="Number of abilities to generate (1–10).",
    )


class AbilitySummary(BaseModel):
    """Lightweight summary returned per generated ability."""

    name: str
    technique: str
    tactic: str
    platform: list[str]
    description: str


class GenerateResponse(BaseModel):
    """Response from /generate."""

    abilities: list[dict[str, Any]]
    count: int
    elapsed_seconds: float
    model: str
    validation_summary: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Safety pipeline summary: counts of passed, blocked, "
            "and warned abilities."
        ),
    )


# ──────────────────────────────────────────────────────────────
# Shared resources (lifespan-managed)
# ──────────────────────────────────────────────────────────────

_engine: ReasoningEngine | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start/stop shared resources (Neo4j, Galaxy, LLM)."""
    global _engine

    settings = get_settings()

    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    )

    logger.info("Starting up — initialising resources...")

    # LLM client
    llm = create_llm_client(settings)
    logger.info("LLM client ready: %s", llm.model_name)

    # Neo4j
    conn = Neo4jConnection()
    logger.info("Neo4j connection ready: %s", settings.neo4j_uri)

    # MISP Galaxy data
    galaxy = GalaxyManager()
    galaxy.load_all()
    logger.info("Galaxy data loaded.")

    # Reasoning engine
    _engine = ReasoningEngine(llm=llm, conn=conn, galaxy=galaxy)
    logger.info("ReasoningEngine ready.")

    yield  # ← app runs here

    # Shutdown
    logger.info("Shutting down...")
    _engine.close()
    _engine = None


# ──────────────────────────────────────────────────────────────
# FastAPI app
# ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="Blackhat Ability Generator",
    description=(
        "Adversary simulation ability compiler — generates MITRE ATT&CK-mapped "
        "abilities via a two-phase LLM reasoning pipeline."
    ),
    version=AGENT_VERSION,
    lifespan=lifespan,
)


@app.get("/health")
async def health():
    """Liveness check."""
    return {"status": "ok", "engine_ready": _engine is not None}


@app.post("/generate", response_model=GenerateResponse)
async def generate_abilities(req: GenerateRequest):
    """Generate attack abilities through the two-phase reasoning pipeline.

    1. **Phase A** — LLM explores the MITRE ATT&CK knowledge graph with
       4 tool closures, selects techniques, gathers threat intelligence.
    2. **Phase B** — For each ability, the LLM produces validated
       structured JSON conforming to the ``Ability`` Pydantic schema.
    """
    if _engine is None:
        raise HTTPException(status_code=503, detail="Engine not initialised.")

    start = time.perf_counter()

    try:
        abilities = _engine.generate_abilities(
            category=req.category,
            platform=req.platform,
            count=req.count,
        )
    except Exception as exc:
        logger.error("Generation failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))

    elapsed = round(time.perf_counter() - start, 2)

    # Compute validation summary from generated abilities
    passed_count = sum(
        1 for a in abilities
        if a.approval_status.value != "BLOCKED"
    )
    blocked_count = sum(
        1 for a in abilities
        if a.approval_status.value == "BLOCKED"
    )
    warned_count = sum(
        1 for a in abilities
        if a.generation_trace
        and len(a.generation_trace.validation_warnings) > 0
    )

    return GenerateResponse(
        abilities=[a.model_dump(mode="json") for a in abilities],
        count=len(abilities),
        elapsed_seconds=elapsed,
        model=_engine.model_name,
        validation_summary={
            "total": len(abilities),
            "passed": passed_count,
            "blocked": blocked_count,
            "warned": warned_count,
        },
    )


# ──────────────────────────────────────────────────────────────
# Direct execution: python -m src.api.main
# ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    _settings = get_settings()
    uvicorn.run(
        "src.api.main:app",
        host=_settings.api_host,
        port=_settings.api_port,
        reload=True,
    )
