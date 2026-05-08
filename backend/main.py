"""
main.py - FastAPI application entry point for SOC Log Analyzer.

Run with:
    uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.database import init_db
from backend.api.routes_logs     import router as logs_router
from backend.api.routes_alerts   import router as alerts_router
from backend.api.routes_reports  import router as reports_router
from backend.utils.logger import get_logger

logger = get_logger(__name__)


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    init_db()
    logger.info("SOC Log Analyzer API started. DB initialised.")
    yield
    logger.info("SOC Log Analyzer API shutting down.")


# ── App Initialisation ────────────────────────────────────────────────────────

app = FastAPI(
    title       = "SOC Log Analyzer API",
    description = "AI-powered Security Operations Center log analysis tool.",
    version     = "1.0.0",
    docs_url    = "/docs",
    redoc_url   = "/redoc",
    lifespan    = lifespan,
)

# Allow the Streamlit dashboard (and any dev frontend) to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins     = ["*"],
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(logs_router)
app.include_router(alerts_router)
app.include_router(reports_router)


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["Health"])
def health():
    return {"status": "ok", "service": "soc-log-analyzer"}


@app.get("/", tags=["Health"])
def root():
    return {
        "message": "SOC Log Analyzer API",
        "docs":    "/docs",
        "redoc":   "/redoc",
    }
