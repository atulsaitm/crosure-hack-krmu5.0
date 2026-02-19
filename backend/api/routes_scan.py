"""Scan API routes."""

import logging
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
        active_scans[scan_id]["status"] = "complete"
        active_scans[scan_id]["result"] = result.model_dump()
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
    """Get scan result."""
    if scan_id not in active_scans:
        logger.warning(f"[SCAN] Result requested for unknown scan {scan_id}")
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = active_scans[scan_id]
    logger.info(f"[SCAN] Result poll for {scan_id}: status={scan['status']}")
    if scan["status"] == "running":
        # Return 202 as a proper JSON response (not HTTPException)
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
