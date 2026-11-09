"""
CyberGuard AI — FastAPI Application Entry Point

Autonomous security assessment and VAPT agent that guides authorized penetration
testing from initial reconnaissance through to client-ready report generation.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from config import settings
from database import init_db
from routers.assessments import router as assessments_router
from routers.chat import router as chat_router
from routers.scans import router as scans_router
from routers.reports import router as reports_router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cyberguard.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialise database schemas and required directories on startup."""
    logger.info("Initializing CyberGuard AI database and directories...")
    os.makedirs(settings.REPORTS_DIR, exist_ok=True)
    os.makedirs("static", exist_ok=True)
    await init_db()
    logger.info("CyberGuard AI database initialized successfully.")
    yield
    logger.info("Shutting down CyberGuard AI service.")


app = FastAPI(
    title="CyberGuard AI — VAPT Assessment Agent",
    description=(
        "Conversational AI agent that guides authorized security assessments from "
        "initial reconnaissance, through evidence correlation and risk prioritization, "
        "to generating client-ready VAPT PDF deliverables."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# CORS configuration to allow local React frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "*",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(assessments_router)
app.include_router(chat_router)
app.include_router(scans_router)
app.include_router(reports_router)

# Mount reports directory for direct download / preview
if not os.path.exists(settings.REPORTS_DIR):
    os.makedirs(settings.REPORTS_DIR, exist_ok=True)
app.mount("/static/reports", StaticFiles(directory=settings.REPORTS_DIR), name="reports")


@app.get("/api/health", tags=["Health"])
async def health_check():
    """Health check endpoint returning service status and security boundary config."""
    return {
        "status": "online",
        "service": "CyberGuard AI",
        "version": "1.0.0",
        "llm_configured": bool(settings.LLM_API_KEY),
        "allowed_targets": settings.allowed_targets,
        "human_approval_required": settings.REQUIRE_HUMAN_APPROVAL_FOR_EXPLOITATION,
    }


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=True,
    )
