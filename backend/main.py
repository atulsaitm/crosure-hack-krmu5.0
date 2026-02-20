import logging
import sys

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import httpx

from config import settings
from kb.database import init_db
from api.routes_scan import router as scan_router
from api.routes_findings import router as findings_router
from api.routes_kb import router as kb_router
from api.ws import router as ws_router

# ── Structured Logging ──────────────────────────────────────────────────────
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-25s | %(message)s"
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    datefmt="%H:%M:%S",
    stream=sys.stdout,
    force=True,
)
# Reduce noise from libraries
logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
logging.getLogger("sqlalchemy").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("chromadb").setLevel(logging.WARNING)
logging.getLogger("onnxruntime").setLevel(logging.WARNING)
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

logger = logging.getLogger("crosure.app")


async def _check_ollama_status() -> dict:
    """Check if Ollama is reachable and has a model loaded."""
    status = {"reachable": False, "models": [], "ready": False}
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{settings.OLLAMA_URL}/api/tags")
            resp.raise_for_status()
            data = resp.json()
            status["reachable"] = True
            status["models"] = [m["name"] for m in data.get("models", [])]
            status["ready"] = len(status["models"]) > 0
    except Exception as e:
        logger.warning(f"Ollama health check failed: {e}")
    return status


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("=" * 60)
    logger.info("CROSURE — AI-Augmented Attack-Chain Vulnerability Scanner")
    logger.info("=" * 60)

    await init_db()
    logger.info("[DB] PostgreSQL initialized")

    # Check Ollama
    ollama_status = await _check_ollama_status()
    if ollama_status["ready"]:
        logger.info(f"[OLLAMA] Connected — models: {', '.join(ollama_status['models'])}")
    elif ollama_status["reachable"]:
        logger.warning(f"[OLLAMA] Connected but NO MODELS loaded! AI triage will use chain-based fallback.")
        logger.warning(f"[OLLAMA] Run: docker compose exec ollama ollama pull {settings.OLLAMA_MODEL}")
    else:
        logger.warning("[OLLAMA] Not reachable — AI features disabled, using chain-based fallback.")

    # Check OpenRouter
    openrouter_ready = False
    if settings.OPENROUTER_API_KEY:
        try:
            from llm.openrouter_client import check_openrouter_available
            openrouter_ready = await check_openrouter_available()
            if openrouter_ready:
                logger.info(f"[OPENROUTER] Connected — model: {settings.OPENROUTER_MODEL} (PRIMARY LLM)")
            else:
                logger.warning("[OPENROUTER] API key set but connection failed")
        except Exception as e:
            logger.warning(f"[OPENROUTER] Check failed: {e}")
    else:
        logger.info("[OPENROUTER] No API key set — using Ollama only")

    llm_mode = "openrouter" if openrouter_ready else ("ollama" if ollama_status["ready"] else "chain_fallback")
    logger.info(f"[LLM] Active backend: {llm_mode}")

    # Warm up Ollama model to avoid cold start timeout during scan
    if ollama_status["ready"]:
        try:
            import httpx as _hx
            async with _hx.AsyncClient(timeout=120.0) as _c:
                logger.info("[OLLAMA] Warming up model (first inference)...")
                await _c.post(
                    f"{settings.OLLAMA_URL}/api/generate",
                    json={"model": settings.OLLAMA_MODEL, "prompt": "hello", "stream": False, "options": {"num_predict": 5}},
                )
                logger.info("[OLLAMA] Model warm — ready for triage")
        except Exception as e:
            logger.warning(f"[OLLAMA] Warmup failed (non-fatal): {e}")

    # Seed Knowledge Base with CVE data if empty
    try:
        from kb.seed_kb import seed_knowledge_base
        seeded = await seed_knowledge_base()
        if seeded:
            logger.info(f"[KB] Seeded {seeded} exploits into knowledge base")
        else:
            logger.info("[KB] Knowledge base already populated")
    except Exception as e:
        logger.warning(f"[KB] Seeding failed (non-fatal): {e}")

    # Store status for health check
    app.state.ollama_status = ollama_status
    app.state.openrouter_ready = openrouter_ready
    app.state.llm_mode = llm_mode

    logger.info("[READY] All systems go — listening on :8000")
    logger.info("=" * 60)
    yield
    logger.info("Crosure shutting down...")



app = FastAPI(
    title=settings.APP_NAME,
    description="Attack-Chain Vulnerability Scanner with Community Exploit Intelligence",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router)
app.include_router(findings_router)
app.include_router(kb_router)
app.include_router(ws_router)


@app.get("/health")
async def health():
    ollama_status = getattr(app.state, "ollama_status", {})
    openrouter_ready = getattr(app.state, "openrouter_ready", False)
    llm_mode = getattr(app.state, "llm_mode", "chain_fallback")
    return {
        "status": "ok",
        "app": settings.APP_NAME,
        "ollama_ready": ollama_status.get("ready", False),
        "ollama_models": ollama_status.get("models", []),
        "openrouter_ready": openrouter_ready,
        "openrouter_model": settings.OPENROUTER_MODEL if openrouter_ready else None,
        "llm_mode": llm_mode,
    }
