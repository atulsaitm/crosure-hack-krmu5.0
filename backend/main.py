from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from config import settings
from kb.database import init_db
from api.routes_scan import router as scan_router
from api.routes_findings import router as findings_router
from api.routes_kb import router as kb_router
from api.ws import router as ws_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_db()
    yield
    # Shutdown


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
    return {"status": "ok", "app": settings.APP_NAME}
