import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan import Scan
from app.models.schemas import (
    ScanRequest,
    ScanResponse,
    ScanHistoryItem,
    CheckResult,
    ErrorResponse,
)
from app.services.scanner import run_scan, get_verdict

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
    _, verdict_color = get_verdict(scan.risk_score)

    return ScanResponse(
        id=scan.id,
        url=scan.url,
        risk_score=scan.risk_score,
        verdict=scan.verdict,
        verdict_color=verdict_color,
        checks=checks,
        redirect_chain=redirect_chain,
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


@router.get("/health")
async def health():
    return {"status": "ok", "service": "PhishScan API"}
