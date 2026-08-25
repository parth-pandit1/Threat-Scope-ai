"""
ThreatScope AI — FastAPI application entry point.
"""

import logging
import json
import httpx
import asyncio
from datetime import datetime, timezone
from typing import Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text, select, func

from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api import scan_file, scan_result, scan_url
from app.core.config import settings
import sentry_sdk

if settings.SENTRY_DSN:
    sentry_sdk.init(
        dsn=settings.SENTRY_DSN,
        traces_sample_rate=1.0,
        profiles_sample_rate=1.0,
    )
from app.core.database import async_session_factory, get_db
from app.core.storage import ensure_bucket_exists, get_minio_client
from app.core.rq_setup import redis_conn
from app.models.scan import Scan, Verdict
from app.core.limiter import limiter

# ── Logging ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(levelname)-8s │ %(name)s │ %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ── Rate Limiter ──────────────────────────────────────────────
# Instantiated in app.core.limiter without default limits to protect monitoring routes


# ── Lifespan (startup / shutdown) ────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("═══ Starting ThreatScope AI backend ═══")

    logger.info("Database migration check completed (run via entrypoint)")

    logger.info(f"Resolved MINIO_ENDPOINT: {settings.MINIO_ENDPOINT}")
    logger.info(f"Resolved MINIO_REGION: {settings.MINIO_REGION}")

    # MinIO bucket
    try:
        client = get_minio_client()
        ensure_bucket_exists(client, settings.MINIO_BUCKET)
        logger.info("MinIO bucket '%s' is ready", settings.MINIO_BUCKET)
    except Exception as exc:
        logger.warning(
            "MinIO connection failed: %s — file uploads will not work until resolved",
            str(exc),
        )

    # YARA rules startup update in the background
    from app.analysis.yara_manager import update_rules
    
    async def init_yara_rules():
        logger.info("Running initial YARA rules update in background...")
        try:
            await asyncio.to_thread(update_rules)
            logger.info("Initial YARA rules update complete")
        except Exception as e:
            logger.error("Failed initial YARA rules update: %s", e)

    asyncio.create_task(init_yara_rules())

    # Schedule weekly YARA updates
    from rq_scheduler import Scheduler
    try:
        scheduler = Scheduler(connection=redis_conn, queue_name='default')
        # Remove any existing schedules for this task to avoid duplicates
        for job in scheduler.get_jobs():
            if job.func_name == 'app.tasks.yara_update.update_yara_rules_task':
                scheduler.cancel(job)
        
        # Schedule weekly refresh
        scheduler.schedule(
            scheduled_time=datetime.now(timezone.utc),
            func='app.tasks.yara_update.update_yara_rules_task',
            interval=7 * 24 * 60 * 60, # 1 week in seconds
            repeat=None
        )
        logger.info("YARA weekly update task scheduled successfully")
    except Exception as e:
        logger.warning("Could not schedule weekly YARA update: %s", e)

    logger.info("═══ ThreatScope AI backend is ready ═══")
    yield
    logger.info("═══ Shutting down ThreatScope AI backend ═══")




# ── FastAPI Application ──────────────────────────────────────
app = FastAPI(
    title="ThreatScope AI",
    description="Threat intelligence and malware analysis platform API.",
    version="1.0.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)



app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Router Registration ─────────────────────────────────────
app.include_router(scan_file.router)
app.include_router(scan_url.router)
app.include_router(scan_result.router)


# ── Health Endpoints ─────────────────────────────────────────
@app.get("/api/health", tags=["Health"], summary="Detailed health check")
async def health_check():
    """
    Detailed health status checking Postgres, Redis, Ollama, MinIO,
    and YARA engine. Returns 200 if all pass, 503 with per-service
    detail if any fail.
    """
    from starlette.responses import JSONResponse
    from app.analysis.yara_manager import get_status as get_yara_status

    health_status: dict[str, Any] = {"status": "healthy"}

    # Check Postgres
    try:
        async with async_session_factory() as session:
            await session.execute(text("SELECT 1"))
        health_status["postgres"] = "up"
    except Exception as e:
        health_status["postgres"] = "down"
        health_status["status"] = "degraded"
        logger.error("Postgres health check failed: %s", e)

    # Check Redis
    try:
        if redis_conn.ping():
            health_status["redis"] = "up"
        else:
            raise Exception("Ping failed")
    except Exception as e:
        health_status["redis"] = "down"
        health_status["status"] = "degraded"
        logger.error("Redis health check failed: %s", e)

    # Check Ollama (2s timeout)
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            ollama_base = settings.OLLAMA_URL.replace("/api/generate", "")
            resp = await client.get(f"{ollama_base}/api/tags")
            health_status["ollama"] = "up" if resp.status_code == 200 else "down"
    except Exception:
        health_status["ollama"] = "down"
        # Ollama is optional — don't mark degraded
        logger.info("Ollama not reachable — AI explanations will use fallback")

    # Check MinIO
    try:
        mc = get_minio_client()
        mc.list_buckets()
        health_status["minio"] = "up"
    except Exception as e:
        health_status["minio"] = "down"
        health_status["status"] = "degraded"
        logger.error("MinIO health check failed: %s", e)

    # YARA engine status
    try:
        yara_stat = get_yara_status()
        health_status["yara"] = {
            "loaded": yara_stat.get("last_updated") is not None,
            "rule_count": yara_stat.get("rule_count", 0),
            "last_updated": yara_stat.get("last_updated"),
        }
    except Exception:
        health_status["yara"] = {"loaded": False, "rule_count": 0, "last_updated": None}

    # Return 503 if any critical service is down
    if health_status["status"] != "healthy":
        return JSONResponse(content=health_status, status_code=503)
    return health_status


@app.get("/api/stats", tags=["Health"], summary="System statistics")
async def get_stats(db = Depends(get_db)):
    """Return total scans and malicious scans, cached."""
    cache_key = "system_stats"
    cached = redis_conn.get(cache_key)
    if cached:
        return json.loads(cached)
        
    try:
        total_scans = await db.scalar(select(func.count(Scan.id)))
        malicious_scans = await db.scalar(select(func.count(Scan.id)).where(Scan.verdict == Verdict.MALICIOUS))
        start_date = await db.scalar(select(func.min(Scan.created_at)))
        
        stats = {
            "total_scans": total_scans or 0,
            "malicious_scans": malicious_scans or 0,
            "start_date": start_date.isoformat() if start_date else None
        }
        
        redis_conn.setex(cache_key, 60, json.dumps(stats))
        return stats
    except Exception as e:
        logger.error(f"Failed to fetch stats: {e}")
        return {"error": "Failed to fetch stats"}
