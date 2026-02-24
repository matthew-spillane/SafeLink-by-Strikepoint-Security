import asyncio
import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.scan import Scan
from app.models.schemas import CheckResult, ScanResponse
from app.services.analyzers import (
    check_virustotal,
    check_google_safe_browsing,
    check_whois_domain_age,
    check_ssl_certificate,
    check_redirect_chain,
    check_suspicious_keywords,
    check_lookalike_domain,
    check_ip_geolocation,
    check_url_structure,
    check_page_content,
)


def calculate_risk_score(checks: list[CheckResult]) -> int:
    score = 0
    for check in checks:
        if check.name == "VirusTotal" and check.status == "fail":
            score += 40
        elif check.name == "Google Safe Browsing" and check.status == "fail":
            score += 40
        elif check.name == "WHOIS / Domain Age":
            if check.details and isinstance(check.details, dict):
                age = check.details.get("age_days")
                if age is not None:
                    if age < 30:
                        score += 20
                    elif age < 180:
                        score += 10
        elif check.name == "SSL Certificate":
            if check.status == "fail":
                details = check.details if isinstance(check.details, dict) else {}
                if details.get("scheme") == "http" or "no SSL" in check.summary.lower() or "does not use HTTPS" in check.summary:
                    score += 15
                else:
                    score += 10  # expired or invalid
        elif check.name == "Redirect Chain":
            if check.status == "fail":
                score += 10
        elif check.name == "Suspicious Keywords":
            if check.details and isinstance(check.details, dict):
                count = len(check.details.get("keywords", []))
                score += min(count * 5, 15)
        elif check.name == "Lookalike Domain" and check.status == "fail":
            score += 25
        elif check.name == "IP Geolocation" and check.status == "warning":
            if check.details and isinstance(check.details, dict) and check.details.get("org"):
                if "abused" in check.summary.lower() or "vps" in check.summary.lower():
                    score += 10
        elif check.name == "URL Structure":
            if check.details and isinstance(check.details, dict):
                flags = check.details.get("flags", [])
                score += min(len(flags) * 5, 20)
        elif check.name == "Page Content":
            if check.details and isinstance(check.details, dict):
                findings = check.details.get("findings", [])
                # Check for login form with domain mismatch
                has_login = any("login form" in f.lower() for f in findings)
                has_mismatch = any("but domain is" in f.lower() for f in findings)
                if has_login and has_mismatch:
                    score += 20
                elif findings:
                    score += min(len(findings) * 5, 15)

    return min(score, 100)


def get_verdict(score: int) -> tuple[str, str]:
    if score <= 25:
        return "Safe", "green"
    elif score <= 50:
        return "Suspicious", "yellow"
    elif score <= 75:
        return "Likely Phishing", "orange"
    return "Phishing", "red"


async def run_scan(url: str, db: Session) -> ScanResponse:
    # Run all checks concurrently
    results = await asyncio.gather(
        check_virustotal(url),
        check_google_safe_browsing(url),
        check_whois_domain_age(url),
        check_ssl_certificate(url),
        check_redirect_chain(url),
        check_suspicious_keywords(url),
        check_lookalike_domain(url),
        check_ip_geolocation(url),
        check_url_structure(url),
        check_page_content(url),
    )

    # Unpack redirect chain (returns tuple)
    checks = []
    redirect_chain = []
    for r in results:
        if isinstance(r, tuple):
            check_result, chain = r
            checks.append(check_result)
            redirect_chain = chain
        else:
            checks.append(r)

    risk_score = calculate_risk_score(checks)
    verdict, verdict_color = get_verdict(risk_score)

    # Save to database
    scan = Scan(
        url=url,
        risk_score=risk_score,
        verdict=verdict,
        results_json=json.dumps({
            "checks": [c.model_dump() for c in checks],
            "redirect_chain": redirect_chain,
        }),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    return ScanResponse(
        id=scan.id,
        url=scan.url,
        risk_score=risk_score,
        verdict=verdict,
        verdict_color=verdict_color,
        checks=checks,
        redirect_chain=redirect_chain,
        created_at=scan.created_at,
    )
