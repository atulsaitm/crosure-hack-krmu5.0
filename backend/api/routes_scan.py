"""Scan API routes with PostgreSQL persistence."""

import logging
from datetime import datetime
from fastapi import APIRouter, HTTPException, BackgroundTasks
from starlette.responses import JSONResponse
from typing import Dict

from core.models import ScanRequest, ScanResponse, ScanPhase, WSEvent
from core.orchestrator import ScanOrchestrator

logger = logging.getLogger("crosure.scan")
logger.setLevel(logging.DEBUG)

router = APIRouter(prefix="/api/scan", tags=["scan"])

# In-memory scan state
active_scans: Dict[str, dict] = {}


async def _persist_scan(scan_id: str, target_url: str, result_dict: dict, status: str = "complete"):
    """Save scan result to PostgreSQL (fire-and-forget)."""
    try:
        from kb.database import async_session, ScanResult
        from sqlalchemy import select

        async with async_session() as session:
            # Check if already exists
            existing = await session.execute(
                select(ScanResult).where(ScanResult.scan_id == scan_id)
            )
            row = existing.scalar_one_or_none()

            if row:
                row.status = status
                row.findings = result_dict.get("findings")
                row.chains_discovered = result_dict.get("chains")
                row.endpoints_discovered = result_dict.get("endpoints_crawled", 0)
                row.completed_at = datetime.utcnow()
            else:
                row = ScanResult(
                    scan_id=scan_id,
                    target_url=target_url,
                    status=status,
                    findings=result_dict.get("findings"),
                    chains_discovered=result_dict.get("chains"),
                    endpoints_discovered=result_dict.get("endpoints_crawled", 0),
                    scan_config=result_dict.get("tech_stack"),
                    started_at=datetime.utcnow(),
                    completed_at=datetime.utcnow() if status == "complete" else None,
                )
                session.add(row)

            await session.commit()
            logger.info(f"[DB] Scan {scan_id} persisted to PostgreSQL")
    except Exception as e:
        logger.warning(f"[DB] Failed to persist scan {scan_id}: {e}")


@router.post("/", response_model=ScanResponse)
async def start_scan(request: ScanRequest):
    """Start a vulnerability scan."""
    from api.ws import broadcast_event

    orchestrator = ScanOrchestrator(ws_callback=broadcast_event)
    scan_id = orchestrator.scan_id

    active_scans[scan_id] = {
        "status": "running",
        "target": request.target_url,
    }

    try:
        result = await orchestrator.run_scan(request)
        result_dict = result.model_dump()
        active_scans[scan_id]["status"] = "complete"
        active_scans[scan_id]["result"] = result_dict
        await _persist_scan(scan_id, request.target_url, result_dict)
        return result
    except Exception as e:
        active_scans[scan_id]["status"] = "error"
        active_scans[scan_id]["error"] = str(e)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/async", response_model=dict)
async def start_scan_async(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a scan in the background. Returns scan_id immediately."""
    from api.ws import broadcast_event

    orchestrator = ScanOrchestrator(ws_callback=broadcast_event)
    scan_id = orchestrator.scan_id
    logger.info(f"[SCAN] Async scan started: {scan_id} target={request.target_url}")

    active_scans[scan_id] = {
        "status": "running",
        "target": request.target_url,
    }

    async def _run():
        try:
            logger.info(f"[SCAN] Background task running for {scan_id}")
            result = await orchestrator.run_scan(request)
            result_dict = result.model_dump()
            active_scans[scan_id]["status"] = "complete"
            active_scans[scan_id]["result"] = result_dict
            logger.info(f"[SCAN] Scan {scan_id} COMPLETE: {len(result_dict.get('findings', []))} findings, {len(result_dict.get('chains', []))} chains")
            await _persist_scan(scan_id, request.target_url, result_dict)
        except Exception as e:
            logger.error(f"[SCAN] Background scan {scan_id} CRASHED: {e}", exc_info=True)
            active_scans[scan_id]["status"] = "error"
            active_scans[scan_id]["error"] = str(e)

    background_tasks.add_task(_run)
    logger.info(f"[SCAN] Returning scan_id={scan_id} to client")

    return {"scan_id": scan_id, "status": "started"}


@router.get("/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Get scan status."""
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return active_scans[scan_id]


@router.get("/{scan_id}/result")
async def get_scan_result(scan_id: str):
    """Get scan result — checks memory first, then DB."""
    if scan_id in active_scans:
        scan = active_scans[scan_id]
        logger.info(f"[SCAN] Result poll for {scan_id}: status={scan['status']}")
        if scan["status"] == "running":
            return JSONResponse(status_code=202, content={"status": "running", "detail": "Scan still in progress"})
        if scan["status"] == "error":
            logger.error(f"[SCAN] Returning error result for {scan_id}: {scan.get('error')}")
            return {
                "scan_id": scan_id,
                "target_url": scan.get("target", ""),
                "findings": [],
                "chains": [],
                "endpoints_crawled": 0,
                "scan_duration": 0,
                "errors": [scan.get("error", "Unknown error")],
            }
        logger.info(f"[SCAN] Returning complete result for {scan_id}")
        return scan["result"]

    # Fallback: check PostgreSQL
    try:
        from kb.database import async_session, ScanResult
        from sqlalchemy import select

        async with async_session() as session:
            result = await session.execute(
                select(ScanResult).where(ScanResult.scan_id == scan_id)
            )
            row = result.scalar_one_or_none()
            if row:
                logger.info(f"[SCAN] Found {scan_id} in DB")
                return {
                    "scan_id": row.scan_id,
                    "target_url": row.target_url,
                    "findings": row.findings or [],
                    "chains": row.chains_discovered or [],
                    "endpoints_crawled": row.endpoints_discovered,
                    "scan_duration": 0,
                }
    except Exception as e:
        logger.warning(f"[SCAN] DB lookup failed: {e}")

    raise HTTPException(status_code=404, detail="Scan not found")


@router.get("/history/list")
async def list_scan_history():
    """List recent scans from database."""
    try:
        from kb.database import async_session, ScanResult
        from sqlalchemy import select

        async with async_session() as session:
            result = await session.execute(
                select(ScanResult).order_by(ScanResult.created_at.desc()).limit(50)
            )
            rows = result.scalars().all()
            return [
                {
                    "scan_id": r.scan_id,
                    "target_url": r.target_url,
                    "status": r.status,
                    "endpoints_discovered": r.endpoints_discovered,
                    "finding_count": len(r.findings) if r.findings else 0,
                    "chain_count": len(r.chains_discovered) if r.chains_discovered else 0,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                }
                for r in rows
            ]
    except Exception as e:
        logger.warning(f"[SCAN] History query failed: {e}")
        return []
