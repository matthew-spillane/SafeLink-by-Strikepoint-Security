import json
import logging

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan import Scan
from app.models.schemas import (
    AIVerdict,
    URLScanResult,
    ScanRequest,
    ScanResponse,
    ScanHistoryItem,
    CheckResult,
    ErrorResponse,
)
from app.services.scanner import run_scan, get_verdict

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api")


@router.post("/scan", response_model=ScanResponse)
async def scan_url(request: ScanRequest, db: Session = Depends(get_db)):
    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required.")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        return await run_scan(url, db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    data = json.loads(scan.results_json)
    checks = [CheckResult(**c) for c in data.get("checks", [])]
    redirect_chain = data.get("redirect_chain", [])
    ai_verdict_data = data.get("ai_verdict")
    ai_verdict = AIVerdict(**ai_verdict_data) if ai_verdict_data else None
    urlscan_data = data.get("urlscan")
    urlscan = URLScanResult(**urlscan_data) if urlscan_data else None
    _, verdict_color = get_verdict(scan.risk_score)

    return ScanResponse(
        id=scan.id,
        url=scan.url,
        risk_score=scan.risk_score,
        verdict=scan.verdict,
        verdict_color=verdict_color,
        checks=checks,
        redirect_chain=redirect_chain,
        ai_verdict=ai_verdict,
        urlscan=urlscan,
        created_at=scan.created_at,
    )


@router.get("/history", response_model=list[ScanHistoryItem])
async def get_history(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(20).all()
    result = []
    for scan in scans:
        _, color = get_verdict(scan.risk_score)
        result.append(
            ScanHistoryItem(
                id=scan.id,
                url=scan.url,
                risk_score=scan.risk_score,
                verdict=scan.verdict,
                verdict_color=color,
                created_at=scan.created_at,
            )
        )
    return result


@router.get("/scan/{scan_id}/urlscan", response_model=URLScanResult)
async def get_urlscan_result(scan_id: str, db: Session = Depends(get_db)):
    """Poll URLscan.io for a completed result. Returns available=True once ready."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    data = json.loads(scan.results_json)
    urlscan_data = data.get("urlscan", {})
    uuid = urlscan_data.get("urlscan_uuid")

    if not uuid:
        return URLScanResult(available=False)

    # If we already have a completed result cached, return it
    if urlscan_data.get("available"):
        return URLScanResult(**urlscan_data)

    # Poll URLscan for result
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"https://urlscan.io/api/v1/result/{uuid}/")
            if resp.status_code != 200:
                # Not ready yet
                return URLScanResult(
                    urlscan_uuid=uuid,
                    report_url=f"https://urlscan.io/result/{uuid}/",
                    screenshot_url=f"https://urlscan.io/screenshots/{uuid}.png",
                    available=False,
                )

            result = resp.json()
            verdicts = result.get("verdicts", {}).get("overall", {})
            malicious = verdicts.get("malicious", False)
            score = verdicts.get("score", 0)
            if malicious:
                verdict_label = "Malicious"
            elif score >= 50:
                verdict_label = "Suspicious"
            elif score > 0:
                verdict_label = "Potentially Suspicious"
            else:
                verdict_label = "Clean"

            completed = URLScanResult(
                urlscan_uuid=uuid,
                screenshot_url=f"https://urlscan.io/screenshots/{uuid}.png",
                verdict=verdict_label,
                report_url=f"https://urlscan.io/result/{uuid}/",
                available=True,
            )

            # Cache the completed result back to DB so future loads are instant
            data["urlscan"] = completed.model_dump()
            scan.results_json = json.dumps(data)
            db.commit()

            return completed
    except Exception as e:
        logger.warning("URLscan poll failed: %s", e)
        return URLScanResult(urlscan_uuid=uuid, available=False)


@router.get("/health")
async def health():
    return {"status": "ok", "service": "SafeLink API"}
