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
    check_shodan_internetdb,
    check_alienvault_otx,
    check_urlscan,
)


def calculate_risk_score(checks: list[CheckResult]) -> int:
    """Calculate risk score with weighted signals.

    Weight budget (100 pts):
      VirusTotal          35  (primary signal)
      Google Safe Browsing 25
      AlienVault OTX       10
      Shodan InternetDB    10
      Contextual checks    20  (domain age, SSL, redirects, keywords,
                                lookalike, IP geo, URL structure,
                                page content)
    """
    score = 0
    for check in checks:
        # --- Primary reputation signals ---
        if check.name == "VirusTotal" and check.status == "fail":
            score += 35
        elif check.name == "Google Safe Browsing" and check.status == "fail":
            score += 25
        elif check.name == "AlienVault OTX":
            details = check.details if isinstance(check.details, dict) else {}
            pulse_count = details.get("pulse_count", 0)
            if pulse_count > 0:
                score += min(pulse_count * 3, 10)
        elif check.name == "Shodan InternetDB":
            details = check.details if isinstance(check.details, dict) else {}
            high_risk = details.get("high_risk_tags") or []
            if high_risk:
                score += 7
            vuln_count = len(details.get("vulns", []))
            if vuln_count > 0:
                score += min(vuln_count * 1, 3)

        # --- Contextual signals (max ~20 pts combined) ---
        elif check.name == "WHOIS / Domain Age":
            if check.details and isinstance(check.details, dict):
                age = check.details.get("age_days")
                if age is not None:
                    if age < 30:
                        score += 4
                    elif age < 180:
                        score += 2
        elif check.name == "SSL Certificate" and check.status == "fail":
            details = check.details if isinstance(check.details, dict) else {}
            if details.get("scheme") == "http" or "no SSL" in check.summary.lower() or "does not use HTTPS" in check.summary:
                score += 3
            else:
                score += 2  # expired or invalid
        elif check.name == "Redirect Chain" and check.status == "fail":
            score += 2
        elif check.name == "Suspicious Keywords":
            if check.details and isinstance(check.details, dict):
                count = len(check.details.get("keywords", []))
                score += min(count * 1, 2)
        elif check.name == "Lookalike Domain" and check.status == "fail":
            score += 4
        elif check.name == "IP Geolocation" and check.status == "warning":
            if check.details and isinstance(check.details, dict) and check.details.get("org"):
                if "abused" in check.summary.lower() or "vps" in check.summary.lower():
                    score += 1
        elif check.name == "URL Structure":
            if check.details and isinstance(check.details, dict):
                flags = check.details.get("flags", [])
                score += min(len(flags) * 1, 2)
        elif check.name == "Page Content":
            if check.details and isinstance(check.details, dict):
                findings = check.details.get("findings", [])
                has_login = any("login form" in f.lower() for f in findings)
                has_mismatch = any("but domain is" in f.lower() for f in findings)
                if has_login and has_mismatch:
                    score += 2
                elif findings:
                    score += min(len(findings), 1)

    return min(score, 100)


def get_verdict(score: int) -> tuple[str, str]:
    if score <= 25:
        return "Safe", "green"
    elif score <= 50:
        return "Suspicious", "yellow"
    elif score <= 75:
        return "Likely Phishing", "orange"
    return "Phishing", "red"


# Points added to risk score based on AI verdict, scaled by confidence
_AI_VERDICT_POINTS: dict[str, int] = {
    "Phishing": 45,
    "Likely Phishing": 35,
    "Suspicious": 25,
    "Safe": 0,
}
_CONFIDENCE_MULTIPLIER: dict[str, float] = {
    "High": 1.0,
    "Medium": 0.75,
    "Low": 0.5,
}
# Minimum score floor for each AI verdict level.  Ensures the final numeric
# score always falls within the same tier as the AI's assessment, so the
# gauge number and the verdict badge label are always consistent.
_AI_VERDICT_FLOOR: dict[str, int] = {
    "Phishing": 76,
    "Likely Phishing": 51,
    "Suspicious": 26,
    "Safe": 0,
}


def apply_ai_score(base_score: int, ai_verdict: "AIVerdict") -> int:
    """Blend AI verdict into the numerical risk score.

    Adds the confidence-scaled point boost to the base score, then raises
    it to a minimum floor so the result always lands in the same verdict
    band as the AI's assessment.  Badge and gauge are always consistent.
    """
    points = _AI_VERDICT_POINTS.get(ai_verdict.verdict, 0)
    multiplier = _CONFIDENCE_MULTIPLIER.get(ai_verdict.confidence, 0.75)
    boosted = base_score + int(points * multiplier)
    floor = _AI_VERDICT_FLOOR.get(ai_verdict.verdict, 0)
    return min(100, max(boosted, floor))


def _rule_based_verdict(risk_score: int) -> "AIVerdict":
    """Fallback verdict when the Anthropic API is unavailable or times out."""
    if risk_score <= 25:
        verdict = "Safe"
        explanation = (
            "No significant threats were detected across all automated checks. "
            "The URL appears legitimate based on available signals, but always "
            "exercise caution when entering personal information online."
        )
    elif risk_score <= 50:
        verdict = "Suspicious"
        explanation = (
            "Some indicators of concern were detected. Exercise caution before "
            "providing any personal information — verify the site is genuine "
            "through an independent search."
        )
    elif risk_score <= 75:
        verdict = "Likely Phishing"
        explanation = (
            "Multiple risk signals suggest this URL may be a phishing attempt. "
            "Avoid entering credentials or personal data. If you were directed "
            "here from an email or message, treat it as suspicious."
        )
    else:
        verdict = "Phishing"
        explanation = (
            "Strong indicators of phishing were detected. This URL is very "
            "likely malicious — do not click, enter information, or interact "
            "with this site."
        )
    return AIVerdict(verdict=verdict, confidence="Medium", explanation=explanation)


logger = logging.getLogger(__name__)

AI_SYSTEM_PROMPT = (
    "You are a senior cybersecurity threat analyst specializing in phishing URL detection. "
    "Analyze the URL and scan results provided, making an independent judgment "
    "about phishing likelihood. "
    "Always examine the raw URL itself carefully: look for brand impersonation, "
    "typosquatting (e.g. 'paypa1.com'), suspicious subdomains (e.g. 'paypal.com.evil.net'), "
    "deceptive URL paths, lookalike characters, and unusual TLDs. "
    "Explicitly flag these patterns even when all reputation API checks return clean results — "
    "a URL can be newly registered and not yet blacklisted while still being malicious. "
    "\n\n"
    "IMPORTANT — Page Content brand keyword false-positive guidance: "
    "Most legitimate websites embed social login buttons (Sign in with Google, Sign in with Apple), "
    "social share widgets (Share on Twitter/Facebook), and OAuth integrations. "
    "Finding brand names like 'Google', 'Apple', 'Twitter', 'Facebook', 'Microsoft', 'Amazon', "
    "or 'PayPal' in page content is completely NORMAL and must NOT be treated as suspicious on its own. "
    "Only treat brand keywords in page content as a risk factor when they appear ALONGSIDE other "
    "concrete red flags such as: a newly registered domain (< 30 days), missing SSL, detections by "
    "VirusTotal or Google Safe Browsing, suspicious redirect chains, or a domain that is a lookalike "
    "of a well-known brand. A well-established site with clean reputation checks should never be "
    "flagged solely because its page content mentions major brand names. "
    "\n\n"
    "You MUST always return a verdict for every URL. "
    "Return ONLY a JSON object with exactly three fields: "
    "verdict (one of: Safe, Suspicious, Likely Phishing, Phishing), "
    "confidence (Low, Medium, or High), and explanation (2-3 sentences in plain "
    "English suitable for non-technical users)."
)


def _call_anthropic_sync(scan_data: dict) -> dict:
    """Run the synchronous Anthropic SDK call (must be called in a thread)."""
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
    return json.loads(text)


async def get_ai_verdict(url: str, checks: list[CheckResult], risk_score: int) -> AIVerdict:
    """Always returns an AIVerdict — falls back to rule-based when API is unavailable."""
    if not ANTHROPIC_API_KEY or anthropic is None:
        return _rule_based_verdict(risk_score)
    try:
        scan_data = {
            "url": url,
            "risk_score": risk_score,
            "checks": [c.model_dump() for c in checks],
        }
        result = await asyncio.wait_for(
            asyncio.to_thread(_call_anthropic_sync, scan_data),
            timeout=5,
        )
        return AIVerdict(
            verdict=result["verdict"],
            confidence=result["confidence"],
            explanation=result["explanation"],
        )
    except asyncio.TimeoutError:
        logger.warning("AI verdict timed out, using rule-based fallback")
        return _rule_based_verdict(risk_score)
    except Exception as e:
        logger.warning("AI verdict failed: %s, using rule-based fallback", e)
        return _rule_based_verdict(risk_score)


async def run_scan(url: str, db: Session, *, session_id: str | None = None) -> ScanResponse:
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
            check_shodan_internetdb(url),
            check_alienvault_otx(url),
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

    base_score = calculate_risk_score(checks)

    # Get AI analyst verdict based on checks + base score
    ai_verdict = await get_ai_verdict(url, checks, base_score)

    # Blend AI verdict contribution into the final risk score
    risk_score = apply_ai_score(base_score, ai_verdict)
    verdict, verdict_color = get_verdict(risk_score)

    # Save to database
    results_data = {
        "checks": [c.model_dump() for c in checks],
        "redirect_chain": redirect_chain,
        "ai_verdict": ai_verdict.model_dump(),
    }
    if urlscan_result:
        results_data["urlscan"] = urlscan_result.model_dump()

    scan = Scan(
        url=url,
        risk_score=risk_score,
        verdict=verdict,
        results_json=json.dumps(results_data),
        session_id=session_id,
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
