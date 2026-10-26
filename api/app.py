"""
Cloud Guardian FastAPI application — v2 with Auth + PostgreSQL.

Run locally:
    uvicorn api.app:app --reload --port 8000

Interactive docs: http://localhost:8000/docs
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

import os

from api.routes import accounts, alerts, auth, billing, dashboard, health, learning, organizations, remediation, scan, simulator, users

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("cloud_guardian.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Cloud Guardian API starting up...")

    from db.engine import init_db
    await init_db()

    logger.info("Cloud Guardian API ready.")
    logger.info("API docs: http://localhost:8000/docs")
    logger.info("Dashboard: http://localhost:3000")
    yield
    logger.info("Cloud Guardian API shutting down.")


app = FastAPI(
    title="Cloud Guardian",
    description=(
        "Autonomous cloud attack detection, MITRE ATT&CK mapping, "
        "and risk-tiered remediation for AWS.\n\n"
        "## Authentication\n"
        "All endpoints except `/health` and `/auth/*` require authentication.\n\n"
        "**JWT:** `Authorization: Bearer <token>` (from `/auth/login`)\n\n"
        "**API Key:** `X-API-Key: cg_live_<key>` (from `/users/me/api-keys`)\n\n"
        "## Roles\n"
        "| Role | Permissions |\n"
        "|------|-------------|\n"
        "| `viewer` | Read-only |\n"
        "| `analyst` | Read + dismiss false positives |\n"
        "| `admin` | Analyst + approve remediations + manage users |\n"
        "| `owner` | Full access + billing + user deactivation |\n"
    ),
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

_cors_origins = [
    o.strip() for o in os.environ.get("CG_CORS_ORIGINS", "").split(",") if o.strip()
]
_cors_credentials = bool(_cors_origins)

from core.rate_limit import RateLimitMiddleware

app.add_middleware(RateLimitMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_cors_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.method} {request.url}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error. Check server logs for details."},
    )


@app.get("/", tags=["System"], include_in_schema=False)
async def root():
    return {"service": "Cloud Guardian", "version": "2.0.0", "docs": "/docs", "health": "/health"}


app.include_router(auth.router)
app.include_router(users.router)
app.include_router(alerts.router)
app.include_router(scan.router)
app.include_router(remediation.router)
app.include_router(accounts.router)
app.include_router(billing.router)
app.include_router(learning.router)
app.include_router(dashboard.router)
app.include_router(organizations.router)
app.include_router(health.router)
app.include_router(simulator.router)
