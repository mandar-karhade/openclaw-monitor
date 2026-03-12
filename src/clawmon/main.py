"""
FastAPI web app serving the OpenClaw exposure dashboard.

Run:
    uvicorn clawmon.main:app --reload --port 8000
"""
from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from clawmon.config import DB_PATH
from clawmon.dashboard.stats import get_dashboard_data
from clawmon.db import get_active_instances, get_unenriched_ips, init_db, update_enrichment
from clawmon.scanner.enricher import enrich_ips

logger = logging.getLogger("clawmon.web")

PROJECT_ROOT = Path(__file__).parent.parent.parent
TEMPLATES_DIR = PROJECT_ROOT / "templates"
STATIC_DIR = PROJECT_ROOT / "static"

db_conn = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global db_conn
    db_conn = await init_db(DB_PATH)
    logger.info("Dashboard started, DB at %s", DB_PATH)

    # Auto-enrich any IPs missing geolocation
    unenriched = await get_unenriched_ips(db_conn)
    if unenriched:
        logger.info("Enriching %d IPs with geolocation...", len(unenriched))
        enrichment = await enrich_ips(unenriched)
        for ip, data in enrichment.items():
            await update_enrichment(db_conn, ip, data)
        logger.info("Enrichment complete")

    yield

    if db_conn:
        await db_conn.close()


app = FastAPI(title="ClawMon", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    data = await get_dashboard_data(db_conn)
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "data": data,
            "data_json": json.dumps(data, default=str),
        },
    )


@app.get("/api/stats")
async def api_stats():
    data = await get_dashboard_data(db_conn)
    return JSONResponse(data)


@app.get("/api/enrich")
async def api_enrich():
    """Trigger geolocation enrichment for unenriched IPs."""
    unenriched = await get_unenriched_ips(db_conn)
    if not unenriched:
        return {"message": "All IPs already enriched", "count": 0}

    enrichment = await enrich_ips(unenriched)
    for ip, data in enrichment.items():
        await update_enrichment(db_conn, ip, data)

    return {"message": f"Enriched {len(enrichment)} IPs", "count": len(enrichment)}
