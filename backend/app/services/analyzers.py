import asyncio
import base64
import logging
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse, unquote

import httpx

try:
    import whois
except ImportError:
    whois = None

try:
    from thefuzz import fuzz
except ImportError:
    fuzz = None

from app.config import VIRUSTOTAL_API_KEY, GOOGLE_SAFE_BROWSING_API_KEY, URLSCAN_API_KEY
from app.models.schemas import CheckResult, URLScanResult

logger = logging.getLogger(__name__)

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm", "banking",
    "paypal", "apple", "amazon", "microsoft", "password", "signin",
    "credential", "suspend", "unusual", "activity", "validate",
]

LEGITIMATE_DOMAINS = [
    "google", "facebook", "paypal", "apple", "amazon", "microsoft",
    "netflix", "instagram", "twitter", "linkedin", "chase", "wellsfargo",
    "bankofamerica",
]

ABUSED_PROVIDERS = [
    "digitalocean", "linode", "vultr", "hetzner", "ovh", "choopa",
    "hostwinds", "contabo",
]

UNCOMMON_TLDS = [".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".icu"]


def _normalize_url_for_vt(url: str) -> str:
    """Normalize a URL for consistent VirusTotal lookups.

    Ensures bare-domain URLs have a trailing slash so that
    ``https://example.com`` and ``https://example.com/`` resolve to the
    same VirusTotal report.
    """
    parsed = urlparse(url)
    path = parsed.path or "/"
    normalized = f"{parsed.scheme}://{parsed.netloc}{path}"
    if parsed.query:
        normalized += f"?{parsed.query}"
    if parsed.fragment:
        normalized += f"#{parsed.fragment}"
    return normalized


def _vt_url_id(url: str) -> str:
    """Compute VirusTotal's URL identifier (base64url without padding)."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _build_vt_result(stats: dict) -> CheckResult:
    """Build a CheckResult from VirusTotal analysis statistics."""
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected
    flagged = malicious + suspicious

    if flagged > 0:
        return CheckResult(
            name="VirusTotal",
            status="fail",
            severity="high",
            summary=f"{flagged} of {total} engines flagged this URL as malicious or suspicious.",
            details=stats,
        )
    return CheckResult(
        name="VirusTotal",
        status="pass",
        severity="low",
        summary=f"0 of {total} engines flagged this URL.",
        details=stats,
    )


async def check_virustotal(url: str) -> CheckResult:
    if not VIRUSTOTAL_API_KEY:
        return CheckResult(
            name="VirusTotal",
            status="skipped",
            severity="info",
            summary="VirusTotal check skipped — API key not configured.",
            details={"reason": "VIRUSTOTAL_API_KEY not set"},
        )
    try:
        normalized = _normalize_url_for_vt(url)
        url_id = _vt_url_id(normalized)
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}

        async with httpx.AsyncClient(timeout=10) as client:
            # --- Step 1: check for an existing report ---
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
            )
            if resp.status_code == 200:
                stats = (
                    resp.json()
                    .get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                )
                if stats:
                    return _build_vt_result(stats)

            # --- Step 2: no cached report — submit a fresh scan ---
            submit = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": normalized},
            )
            if submit.status_code != 200:
                return CheckResult(
                    name="VirusTotal",
                    status="warning",
                    severity="medium",
                    summary="VirusTotal returned an unexpected response.",
                    details={"status_code": submit.status_code},
                )

            analysis_id = submit.json().get("data", {}).get("id", "")
            if not analysis_id:
                return CheckResult(
                    name="VirusTotal",
                    status="warning",
                    severity="medium",
                    summary="VirusTotal did not return an analysis ID.",
                    details={},
                )

            # --- Step 3: poll until the analysis completes ---
            for delay in (3, 5, 8):
                await asyncio.sleep(delay)
                report = await client.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers=headers,
                )
                if report.status_code == 200:
                    attrs = report.json().get("data", {}).get("attributes", {})
                    if attrs.get("status") == "completed":
                        return _build_vt_result(attrs.get("stats", {}))

            # Analysis still running — return a warning rather than silence
            return CheckResult(
                name="VirusTotal",
                status="warning",
                severity="medium",
                summary="VirusTotal scan is still processing — results may be incomplete.",
                details={"analysis_id": analysis_id},
            )
    except Exception as e:
        return CheckResult(
            name="VirusTotal",
            status="warning",
            severity="medium",
            summary=f"VirusTotal check failed: {str(e)}",
            details={"error": str(e)},
        )


async def check_google_safe_browsing(url: str) -> CheckResult:
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return CheckResult(
            name="Google Safe Browsing",
            status="skipped",
            severity="info",
            summary="Google Safe Browsing check skipped — API key not configured.",
            details={"reason": "GOOGLE_SAFE_BROWSING_API_KEY not set"},
        )
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            payload = {
                "client": {"clientId": "safelink", "clientVersion": "1.0.0"},
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION",
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }
            resp = await client.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}",
                json=payload,
            )
            if resp.status_code == 200:
                data = resp.json()
                matches = data.get("matches", [])
                if matches:
                    threat_types = [m.get("threatType", "UNKNOWN") for m in matches]
                    return CheckResult(
                        name="Google Safe Browsing",
                        status="fail",
                        severity="high",
                        summary=f"URL flagged by Google Safe Browsing: {', '.join(threat_types)}.",
                        details={"threats": threat_types},
                    )
                return CheckResult(
                    name="Google Safe Browsing",
                    status="pass",
                    severity="low",
                    summary="URL not found in Google Safe Browsing threat lists.",
                    details={},
                )
            return CheckResult(
                name="Google Safe Browsing",
                status="warning",
                severity="medium",
                summary="Google Safe Browsing returned an unexpected response.",
                details={"status_code": resp.status_code},
            )
    except Exception as e:
        return CheckResult(
            name="Google Safe Browsing",
            status="warning",
            severity="medium",
            summary=f"Google Safe Browsing check failed: {str(e)}",
            details={"error": str(e)},
        )


async def check_whois_domain_age(url: str) -> CheckResult:
    if whois is None:
        return CheckResult(
            name="WHOIS / Domain Age",
            status="skipped",
            severity="info",
            summary="WHOIS check unavailable — dependency not installed.",
            details={"reason": "python-whois not installed"},
        )
    try:
        domain = urlparse(url).hostname
        if not domain:
            return CheckResult(
                name="WHOIS / Domain Age",
                status="warning",
                severity="medium",
                summary="Could not extract domain from URL.",
                details={},
            )
        w = await asyncio.wait_for(asyncio.to_thread(whois.whois, domain), timeout=5)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is None:
            return CheckResult(
                name="WHOIS / Domain Age",
                status="warning",
                severity="medium",
                summary="Domain registration date not available.",
                details={"domain": domain},
            )
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        age_days = (now - creation_date).days
        if age_days < 30:
            return CheckResult(
                name="WHOIS / Domain Age",
                status="fail",
                severity="high",
                summary=f"Domain is only {age_days} days old — high risk for phishing.",
                details={"domain": domain, "created": str(creation_date), "age_days": age_days},
            )
        elif age_days < 180:
            return CheckResult(
                name="WHOIS / Domain Age",
                status="warning",
                severity="medium",
                summary=f"Domain is {age_days} days old — relatively new.",
                details={"domain": domain, "created": str(creation_date), "age_days": age_days},
            )
        return CheckResult(
            name="WHOIS / Domain Age",
            status="pass",
            severity="low",
            summary=f"Domain is {age_days} days old — established domain.",
            details={"domain": domain, "created": str(creation_date), "age_days": age_days},
        )
    except Exception as e:
        return CheckResult(
            name="WHOIS / Domain Age",
            status="warning",
            severity="medium",
            summary=f"WHOIS lookup failed: {str(e)}",
            details={"error": str(e)},
        )


async def check_ssl_certificate(url: str) -> CheckResult:
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if parsed.scheme != "https":
            return CheckResult(
                name="SSL Certificate",
                status="fail",
                severity="high",
                summary="Site does not use HTTPS — no SSL/TLS encryption.",
                details={"scheme": parsed.scheme},
            )

        def _get_cert():
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(5)
                s.connect((hostname, port))
                return s.getpeercert()

        cert = await asyncio.wait_for(asyncio.to_thread(_get_cert), timeout=5)
        issuer = dict(x[0] for x in cert.get("issuer", []))
        not_after = ssl.cert_time_to_seconds(cert["notAfter"])
        expiry_dt = datetime.fromtimestamp(not_after, tz=timezone.utc)
        now = datetime.now(timezone.utc)
        issuer_cn = issuer.get("commonName", "Unknown")

        details = {
            "issuer": issuer_cn,
            "expires": str(expiry_dt),
            "subject": dict(x[0] for x in cert.get("subject", [])),
        }

        if expiry_dt < now:
            return CheckResult(
                name="SSL Certificate",
                status="fail",
                severity="high",
                summary=f"SSL certificate is expired (expired {expiry_dt.date()}).",
                details=details,
            )
        return CheckResult(
            name="SSL Certificate",
            status="pass",
            severity="low",
            summary=f"Valid SSL certificate issued by {issuer_cn}, expires {expiry_dt.date()}.",
            details=details,
        )
    except ssl.SSLCertVerificationError as e:
        return CheckResult(
            name="SSL Certificate",
            status="fail",
            severity="high",
            summary=f"SSL certificate verification failed: {str(e)}",
            details={"error": str(e)},
        )
    except Exception as e:
        return CheckResult(
            name="SSL Certificate",
            status="warning",
            severity="medium",
            summary=f"Could not verify SSL certificate: {str(e)}",
            details={"error": str(e)},
        )


async def check_redirect_chain(url: str) -> tuple[CheckResult, list[str]]:
    chain = [url]
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=5) as client:
            current_url = url
            for _ in range(5):
                resp = await client.get(current_url)
                if resp.is_redirect:
                    location = str(resp.headers.get("location", ""))
                    if location.startswith("/"):
                        parsed = urlparse(current_url)
                        location = f"{parsed.scheme}://{parsed.netloc}{location}"
                    chain.append(location)
                    current_url = location
                else:
                    break

        hops = len(chain) - 1
        domains = set(urlparse(u).hostname for u in chain)
        cross_domain = len(domains) > 1

        if hops > 3:
            return (
                CheckResult(
                    name="Redirect Chain",
                    status="fail",
                    severity="high",
                    summary=f"URL has {hops} redirects — excessive redirect chain detected.",
                    details={"hops": hops, "chain": chain, "cross_domain": cross_domain},
                ),
                chain,
            )
        elif cross_domain and hops > 0:
            return (
                CheckResult(
                    name="Redirect Chain",
                    status="warning",
                    severity="medium",
                    summary=f"URL redirects across {len(domains)} different domains ({hops} hops).",
                    details={"hops": hops, "chain": chain, "cross_domain": cross_domain},
                ),
                chain,
            )
        elif hops > 0:
            return (
                CheckResult(
                    name="Redirect Chain",
                    status="pass",
                    severity="low",
                    summary=f"URL has {hops} redirect(s) within the same domain.",
                    details={"hops": hops, "chain": chain, "cross_domain": cross_domain},
                ),
                chain,
            )
        return (
            CheckResult(
                name="Redirect Chain",
                status="pass",
                severity="low",
                summary="No redirects detected.",
                details={"hops": 0, "chain": chain, "cross_domain": False},
            ),
            chain,
        )
    except Exception as e:
        return (
            CheckResult(
                name="Redirect Chain",
                status="warning",
                severity="medium",
                summary=f"Could not follow redirects: {str(e)}",
                details={"error": str(e), "chain": chain},
            ),
            chain,
        )


async def check_suspicious_keywords(url: str) -> CheckResult:
    url_lower = url.lower()
    found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if found:
        return CheckResult(
            name="Suspicious Keywords",
            status="warning" if len(found) <= 2 else "fail",
            severity="medium" if len(found) <= 2 else "high",
            summary=f"Found {len(found)} suspicious keyword(s) in URL: {', '.join(found)}.",
            details={"keywords": found},
        )
    return CheckResult(
        name="Suspicious Keywords",
        status="pass",
        severity="low",
        summary="No suspicious keywords detected in the URL.",
        details={"keywords": []},
    )


async def check_lookalike_domain(url: str) -> CheckResult:
    if fuzz is None:
        return CheckResult(
            name="Lookalike Domain",
            status="skipped",
            severity="info",
            summary="Lookalike domain check unavailable — dependency not installed.",
            details={"reason": "thefuzz not installed"},
        )
    try:
        hostname = urlparse(url).hostname or ""
        domain_parts = hostname.replace("www.", "").split(".")
        domain_name = domain_parts[0] if domain_parts else hostname

        matches = []
        for legit in LEGITIMATE_DOMAINS:
            ratio = fuzz.ratio(domain_name.lower(), legit.lower())
            if ratio >= 80 and domain_name.lower() != legit.lower():
                matches.append({"legitimate": legit, "similarity": ratio})

        if matches:
            best = max(matches, key=lambda x: x["similarity"])
            return CheckResult(
                name="Lookalike Domain",
                status="fail",
                severity="high",
                summary=f"Domain '{domain_name}' looks similar to '{best['legitimate']}' ({best['similarity']}% match) — possible typosquatting.",
                details={"matches": matches},
            )
        return CheckResult(
            name="Lookalike Domain",
            status="pass",
            severity="low",
            summary="Domain does not closely resemble any known brands.",
            details={"domain": domain_name},
        )
    except Exception as e:
        return CheckResult(
            name="Lookalike Domain",
            status="warning",
            severity="medium",
            summary=f"Lookalike domain check failed: {str(e)}",
            details={"error": str(e)},
        )


async def check_ip_geolocation(url: str) -> CheckResult:
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return CheckResult(
                name="IP Geolocation",
                status="warning",
                severity="medium",
                summary="Could not extract hostname.",
                details={},
            )
        ip = await asyncio.wait_for(asyncio.to_thread(socket.gethostbyname, hostname), timeout=5)
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"https://ipinfo.io/{ip}/json")
            if resp.status_code == 200:
                data = resp.json()
                org = data.get("org", "").lower()
                country = data.get("country", "Unknown")
                org_name = data.get("org", "Unknown")
                city = data.get("city", "Unknown")

                is_abused_provider = any(p in org for p in ABUSED_PROVIDERS)
                if is_abused_provider:
                    return CheckResult(
                        name="IP Geolocation",
                        status="warning",
                        severity="medium",
                        summary=f"Hosted on VPS provider commonly abused by phishers ({org_name}) in {country}.",
                        details={"ip": ip, "country": country, "org": org_name, "city": city},
                    )
                return CheckResult(
                    name="IP Geolocation",
                    status="pass",
                    severity="low",
                    summary=f"Hosted in {city}, {country} by {org_name}.",
                    details={"ip": ip, "country": country, "org": org_name, "city": city},
                )
        return CheckResult(
            name="IP Geolocation",
            status="warning",
            severity="medium",
            summary="Could not retrieve geolocation data.",
            details={"ip": ip},
        )
    except Exception as e:
        return CheckResult(
            name="IP Geolocation",
            status="warning",
            severity="medium",
            summary=f"IP geolocation check failed: {str(e)}",
            details={"error": str(e)},
        )


async def check_url_structure(url: str) -> CheckResult:
    flags = []
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # Check for IP address instead of domain
    try:
        socket.inet_aton(hostname)
        flags.append("Uses IP address instead of domain name")
    except socket.error:
        pass

    # Count subdomains
    parts = hostname.split(".")
    if len(parts) > 4:
        flags.append(f"Excessive subdomains ({len(parts) - 2} levels)")

    # Long URL
    if len(url) > 100:
        flags.append(f"Very long URL ({len(url)} characters)")

    # URL-encoded characters
    if "%" in url and url != unquote(url):
        flags.append("Contains URL-encoded characters")

    # Uncommon TLD
    for tld in UNCOMMON_TLDS:
        if hostname.endswith(tld):
            flags.append(f"Uses uncommon TLD ({tld})")
            break

    # @ symbol
    if "@" in url:
        flags.append("Contains @ symbol — may be attempting URL obfuscation")

    if flags:
        severity = "high" if len(flags) >= 3 else "medium"
        return CheckResult(
            name="URL Structure",
            status="fail" if len(flags) >= 3 else "warning",
            severity=severity,
            summary=f"{len(flags)} structural red flag(s) detected.",
            details={"flags": flags},
        )
    return CheckResult(
        name="URL Structure",
        status="pass",
        severity="low",
        summary="URL structure appears normal.",
        details={"flags": []},
    )


async def check_page_content(url: str) -> CheckResult:
    try:
        async with httpx.AsyncClient(timeout=5, follow_redirects=True) as client:
            resp = await client.get(url)
            content = resp.text[:51200]  # first ~50KB
            content_lower = content.lower()
            parsed = urlparse(url)
            domain = parsed.hostname or ""

            findings = []

            # Password input fields
            if 'type="password"' in content_lower or "type='password'" in content_lower:
                findings.append("Page contains password input field(s)")

            # Login form indicators
            login_indicators = ["login", "sign in", "log in", "authenticate"]
            if any(ind in content_lower for ind in login_indicators):
                if "<form" in content_lower:
                    findings.append("Page contains a login form")

            # Brand name mismatch
            brand_keywords = [
                "paypal", "google", "facebook", "apple", "amazon",
                "microsoft", "netflix", "instagram", "twitter", "linkedin",
                "chase", "wells fargo", "bank of america",
            ]
            mentioned_brands = [b for b in brand_keywords if b in content_lower]
            for brand in mentioned_brands:
                if brand.replace(" ", "") not in domain.lower():
                    findings.append(f"References '{brand}' but domain is '{domain}'")

            # Form action to external domain
            import re as _re
            form_actions = _re.findall(r'action=["\']([^"\']+)["\']', content_lower)
            for action in form_actions:
                if action.startswith("http"):
                    action_domain = urlparse(action).hostname
                    if action_domain and action_domain != domain:
                        findings.append(f"Form submits data to external domain: {action_domain}")

            if findings:
                severity = "high" if len(findings) >= 2 else "medium"
                return CheckResult(
                    name="Page Content",
                    status="fail" if severity == "high" else "warning",
                    severity=severity,
                    summary=f"{len(findings)} suspicious content indicator(s) found.",
                    details={"findings": findings},
                )
            return CheckResult(
                name="Page Content",
                status="pass",
                severity="low",
                summary="No suspicious content patterns detected on the page.",
                details={"findings": []},
            )
    except Exception as e:
        return CheckResult(
            name="Page Content",
            status="warning",
            severity="medium",
            summary=f"Could not fetch page content: {str(e)}",
            details={"error": str(e)},
        )


async def check_cloudflare_radar(url: str) -> CheckResult:
    """Submit URL to Cloudflare Radar URL Scanner and poll for results."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return CheckResult(
                name="Cloudflare Radar",
                status="skipped",
                severity="info",
                summary="Could not extract hostname from URL.",
                details={},
            )

        scan_api = "https://radar.cloudflare.com/api/scan"
        poll_interval = 10  # seconds between polls
        max_wait = 90       # total seconds before timeout

        async with httpx.AsyncClient(timeout=15) as client:
            # Step 1: Submit the URL for scanning
            submit_resp = await client.post(scan_api, json={"url": url})

            if submit_resp.status_code not in (200, 201, 202):
                return CheckResult(
                    name="Cloudflare Radar",
                    status="warning",
                    severity="medium",
                    summary=f"Cloudflare Radar: scan submission returned HTTP {submit_resp.status_code}.",
                    details={
                        "malicious": None,
                        "phishing_detected": None,
                        "domain_categories": [],
                        "radar_rank": 0,
                        "redirect_chain": None,
                        "certificates": None,
                        "technologies": None,
                        "hosting_country": None,
                        "hosting_asn": None,
                        "error": f"HTTP {submit_resp.status_code}",
                    },
                )

            submit_data = submit_resp.json()
            scan_id = (
                submit_data.get("uuid")
                or submit_data.get("scanId")
                or submit_data.get("scan_id")
                or submit_data.get("id")
            )

            if not scan_id:
                # No scan ID means we cannot poll — treat as inconclusive
                # Do NOT parse the submit response as a result; it has no
                # verdicts and would produce a false clean verdict.
                logger.warning(
                    "Cloudflare Radar: no scan ID in submit response for %s: %s",
                    hostname,
                    list(submit_data.keys()),
                )
                return CheckResult(
                    name="Cloudflare Radar",
                    status="warning",
                    severity="medium",
                    summary=f"Cloudflare Radar: scan submitted but no scan ID returned for '{hostname}'.",
                    details={
                        "malicious": None,
                        "phishing_detected": None,
                        "domain_categories": [],
                        "radar_rank": 0,
                        "redirect_chain": None,
                        "certificates": None,
                        "technologies": None,
                        "hosting_country": None,
                        "hosting_asn": None,
                        "error": "No scan ID in submit response",
                    },
                )

            # Step 2: Poll until scan completes or timeout
            elapsed = 0
            scan_data = None
            while elapsed < max_wait:
                await asyncio.sleep(poll_interval)
                elapsed += poll_interval

                poll_resp = await client.get(f"{scan_api}/{scan_id}")
                if poll_resp.status_code != 200:
                    continue

                poll_data = poll_resp.json()
                scan_status = (
                    poll_data.get("status")
                    or poll_data.get("scan", {}).get("status")
                )

                if scan_status in ("completed", "finished", "done"):
                    scan_data = poll_data
                    break
                elif scan_status in ("error", "failed"):
                    return CheckResult(
                        name="Cloudflare Radar",
                        status="warning",
                        severity="medium",
                        summary=f"Cloudflare Radar: scan failed for '{hostname}'.",
                        details={
                            "malicious": None,
                            "phishing_detected": None,
                            "domain_categories": [],
                            "radar_rank": 0,
                            "redirect_chain": None,
                            "certificates": None,
                            "technologies": None,
                            "hosting_country": None,
                            "hosting_asn": None,
                            "error": "Cloudflare scan reported failure",
                        },
                    )

            # Step 3: Handle timeout — never return false safe
            if scan_data is None:
                return CheckResult(
                    name="Cloudflare Radar",
                    status="warning",
                    severity="medium",
                    summary=f"Cloudflare Radar: scan timed out after {max_wait}s for '{hostname}'.",
                    details={
                        "malicious": None,
                        "phishing_detected": None,
                        "domain_categories": [],
                        "radar_rank": 0,
                        "redirect_chain": None,
                        "certificates": None,
                        "technologies": None,
                        "hosting_country": None,
                        "hosting_asn": None,
                        "timeout": True,
                    },
                )

            # Step 4: Parse completed scan results
            return _parse_cloudflare_result(scan_data, hostname)

    except Exception as e:
        logger.warning("Cloudflare Radar check failed: %s", e)
        return CheckResult(
            name="Cloudflare Radar",
            status="warning",
            severity="medium",
            summary=f"Cloudflare Radar: check failed — {str(e)}",
            details={
                "malicious": None,
                "phishing_detected": None,
                "domain_categories": [],
                "radar_rank": 0,
                "redirect_chain": None,
                "certificates": None,
                "technologies": None,
                "hosting_country": None,
                "hosting_asn": None,
                "error": str(e),
            },
        )


def _parse_cloudflare_result(data: dict, hostname: str) -> CheckResult:
    """Parse a completed Cloudflare Radar scan response into a CheckResult."""
    # Cloudflare returns verdicts at verdicts.overall.malicious / .phishing
    verdicts = data.get("verdicts", data.get("scan", {}).get("verdicts", {}))
    overall = verdicts.get("overall", {})

    # Use None as sentinel — if the field is absent the scan data is
    # incomplete and we must NOT default to False (clean).
    raw_malicious = overall.get("malicious")
    raw_phishing = overall.get("phishing")
    raw_phishing_cat = overall.get("categories", {}).get("phishing")

    is_malicious = bool(raw_malicious) if raw_malicious is not None else None
    is_phishing = (
        bool(raw_phishing or raw_phishing_cat)
        if (raw_phishing is not None or raw_phishing_cat is not None)
        else None
    )

    categories = (
        data.get("categories", [])
        or data.get("scan", {}).get("categories", [])
    )
    rank = (
        data.get("rank", 0)
        or data.get("scan", {}).get("rank", 0)
        or data.get("popularity_rank", 0)
    )

    # Extract additional fields if available
    scan_obj = data.get("scan", data)
    hosting_country = scan_obj.get("hosting_country") or scan_obj.get("country")
    hosting_asn = scan_obj.get("hosting_asn") or scan_obj.get("asn")
    technologies = scan_obj.get("technologies")
    certificates = scan_obj.get("certificates")
    redirect_chain = scan_obj.get("redirect_chain")

    details = {
        "malicious": is_malicious,
        "phishing_detected": is_phishing,
        "domain_categories": categories if isinstance(categories, list) else [],
        "radar_rank": rank or 0,
        "redirect_chain": redirect_chain,
        "certificates": certificates,
        "technologies": technologies,
        "hosting_country": hosting_country,
        "hosting_asn": hosting_asn,
    }

    if is_malicious is True:
        status = "fail"
        summary = f"Cloudflare Radar: domain '{hostname}' flagged as malicious."
    elif is_phishing is True:
        status = "fail"
        summary = f"Cloudflare Radar: domain '{hostname}' flagged for phishing."
    elif is_malicious is None and is_phishing is None:
        # Verdicts were absent from the response — inconclusive
        status = "warning"
        summary = f"Cloudflare Radar: no verdict data returned for '{hostname}'."
    else:
        # Explicitly False — Cloudflare confirmed clean
        status = "pass"
        summary = f"Cloudflare Radar: domain '{hostname}' appears clean."

    severity = "high" if status == "fail" else ("medium" if status == "warning" else "low")

    return CheckResult(
        name="Cloudflare Radar",
        status=status,
        severity=severity,
        summary=summary,
        details=details,
    )


async def check_shodan_internetdb(url: str) -> CheckResult:
    """Query Shodan InternetDB for host intelligence (free, no API key needed)."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return CheckResult(
                name="Shodan InternetDB",
                status="skipped",
                severity="info",
                summary="Could not extract hostname from URL.",
                details={},
            )

        # Resolve hostname to IP
        ip = await asyncio.wait_for(
            asyncio.to_thread(socket.gethostbyname, hostname), timeout=5
        )

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"https://internetdb.shodan.io/{ip}")

        details = {
            "ip": ip,
            "ports": [],
            "tags": [],
            "vulns": [],
            "hostnames": [],
            "cpes": [],
            "high_risk_tags": None,
        }

        if resp.status_code == 200:
            data = resp.json()
            details["ports"] = data.get("ports", [])
            details["tags"] = data.get("tags", [])
            details["vulns"] = data.get("vulns", [])
            details["hostnames"] = data.get("hostnames", [])
            details["cpes"] = data.get("cpes", [])

            # Flag high-risk tags
            high_risk = {"vpn", "tor", "proxy", "compromised", "c2", "botnet"}
            found_high_risk = [
                t for t in details["tags"]
                if t.lower() in high_risk
            ]
            if found_high_risk:
                details["high_risk_tags"] = found_high_risk

        vuln_count = len(details["vulns"])
        has_high_risk = details["high_risk_tags"] and len(details["high_risk_tags"]) > 0

        if has_high_risk:
            status = "fail"
            severity = "high"
            summary = f"Shodan InternetDB: host {ip} has high-risk tags: {', '.join(details['high_risk_tags'])}."
        elif vuln_count > 0:
            status = "warning"
            severity = "medium"
            summary = f"Shodan InternetDB: host {ip} has {vuln_count} known CVE(s)."
        else:
            port_count = len(details["ports"])
            status = "pass"
            severity = "low"
            summary = f"Shodan InternetDB: host {ip} has {port_count} open port(s), no known vulnerabilities."

        return CheckResult(
            name="Shodan InternetDB",
            status=status,
            severity=severity,
            summary=summary,
            details=details,
        )
    except Exception as e:
        logger.warning("Shodan InternetDB check failed: %s", e)
        return CheckResult(
            name="Shodan InternetDB",
            status="pass",
            severity="low",
            summary="Shodan InternetDB: could not query API, treating as clean.",
            details={
                "ip": None,
                "ports": [],
                "tags": [],
                "vulns": [],
                "hostnames": [],
                "cpes": [],
                "high_risk_tags": None,
                "error": str(e),
            },
        )


async def check_alienvault_otx(url: str) -> CheckResult:
    """Query AlienVault OTX for threat intelligence on the domain."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return CheckResult(
                name="AlienVault OTX",
                status="skipped",
                severity="info",
                summary="Could not extract hostname from URL.",
                details={},
            )

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{hostname}/general"
            )

        details = {
            "pulse_count": 0,
            "tags": [],
        }

        if resp.status_code == 200:
            data = resp.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            # Collect unique tags from pulses
            pulses = data.get("pulse_info", {}).get("pulses", [])
            all_tags = []
            for pulse in pulses[:20]:  # cap to avoid huge lists
                all_tags.extend(pulse.get("tags", []))
            unique_tags = list(dict.fromkeys(all_tags))[:30]

            details["pulse_count"] = pulse_count
            details["tags"] = unique_tags

        pulse_count = details["pulse_count"]
        if pulse_count > 0:
            status = "warning"
            severity = "medium"
            summary = f"AlienVault OTX: {pulse_count} threat pulse{'s' if pulse_count != 1 else ''} found for {hostname}."
        else:
            status = "pass"
            severity = "low"
            summary = f"AlienVault OTX: no threat pulses found for {hostname}."

        return CheckResult(
            name="AlienVault OTX",
            status=status,
            severity=severity,
            summary=summary,
            details=details,
        )
    except Exception as e:
        logger.warning("AlienVault OTX check failed: %s", e)
        return CheckResult(
            name="AlienVault OTX",
            status="pass",
            severity="low",
            summary="AlienVault OTX: could not query API, treating as clean.",
            details={
                "pulse_count": 0,
                "tags": [],
                "error": str(e),
            },
        )


async def check_urlscan(url: str) -> URLScanResult:
    """Submit URL to URLscan.io and return immediately with UUID (no polling)."""
    if not URLSCAN_API_KEY:
        return URLScanResult(available=False)
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(
                "https://urlscan.io/api/v1/scan/",
                headers={"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"},
                json={"url": url, "visibility": "public"},
            )
            if resp.status_code != 200:
                return URLScanResult(available=False)
            uuid = resp.json().get("uuid", "")
            if not uuid:
                return URLScanResult(available=False)
            return URLScanResult(
                urlscan_uuid=uuid,
                report_url=f"https://urlscan.io/result/{uuid}/",
                screenshot_url=f"https://urlscan.io/screenshots/{uuid}.png",
                available=False,  # not ready yet — frontend will poll
            )
    except Exception as e:
        logger.warning("URLscan submit failed: %s", e)
        return URLScanResult(available=False)
