import asyncio
import json
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

try:
    import anthropic
except ImportError:
    anthropic = None

from app.config import ANTHROPIC_API_KEY
from app.models.scan import Scan
from app.models.schemas import AIVerdict, CheckResult, ScanResponse, URLScanResult
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
    check_urlscan,
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


logger = logging.getLogger(__name__)

AI_SYSTEM_PROMPT = (
    "You are a senior cybersecurity threat analyst. Analyze the following URL "
    "scan results and make an independent judgment about phishing likelihood. "
    "Look holistically at all signals — URL structure, domain name, keywords, "
    "age, SSL, redirects. Explicitly call out brand impersonation patterns even "
    "if reputation APIs return clean results. Return a JSON object with three "
    "fields: verdict (one of: Safe, Suspicious, Likely Phishing, Phishing), "
    "confidence (Low, Medium, or High), and explanation (2-3 sentences in plain "
    "English suitable for non-technical users)."
)


async def get_ai_verdict(url: str, checks: list[CheckResult], risk_score: int) -> AIVerdict | None:
    if not ANTHROPIC_API_KEY or anthropic is None:
        return None
    try:
        scan_data = {
            "url": url,
            "risk_score": risk_score,
            "checks": [c.model_dump() for c in checks],
        }
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        message = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=300,
            system=AI_SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": f"Analyze this URL scan:\n{json.dumps(scan_data, indent=2)}"},
            ],
        )
        text = message.content[0].text.strip()
        # Strip markdown code fences if present
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"):
                text = text[:-3].strip()
        result = json.loads(text)
        return AIVerdict(
            verdict=result["verdict"],
            confidence=result["confidence"],
            explanation=result["explanation"],
        )
    except Exception as e:
        logger.warning("AI verdict failed: %s", e)
        return None


async def run_scan(url: str, db: Session) -> ScanResponse:
    # Run all checks and URLscan concurrently
    check_results, urlscan_result = await asyncio.gather(
        asyncio.gather(
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
        ),
        check_urlscan(url),
    )

    # Unpack redirect chain (returns tuple)
    checks = []
    redirect_chain = []
    for r in check_results:
        if isinstance(r, tuple):
            check_result, chain = r
            checks.append(check_result)
            redirect_chain = chain
        else:
            checks.append(r)

    risk_score = calculate_risk_score(checks)
    verdict, verdict_color = get_verdict(risk_score)

    # Get AI analyst verdict
    ai_verdict = await get_ai_verdict(url, checks, risk_score)

    # Save to database
    results_data = {
        "checks": [c.model_dump() for c in checks],
        "redirect_chain": redirect_chain,
    }
    if ai_verdict:
        results_data["ai_verdict"] = ai_verdict.model_dump()
    if urlscan_result:
        results_data["urlscan"] = urlscan_result.model_dump()

    scan = Scan(
        url=url,
        risk_score=risk_score,
        verdict=verdict,
        results_json=json.dumps(results_data),
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
        ai_verdict=ai_verdict,
        urlscan=urlscan_result,
        created_at=scan.created_at,
    )
