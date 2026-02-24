import asyncio
import hashlib
import re
import socket
import ssl
import struct
from datetime import datetime, timezone
from urllib.parse import urlparse, unquote

import httpx
import whois
from thefuzz import fuzz

from app.config import VIRUSTOTAL_API_KEY, GOOGLE_SAFE_BROWSING_API_KEY
from app.models.schemas import CheckResult

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
        url_id = hashlib.sha256(url.encode()).hexdigest()
        async with httpx.AsyncClient(timeout=30) as client:
            # Submit URL for scanning
            resp = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
                data={"url": url},
            )
            if resp.status_code == 200:
                analysis_id = resp.json().get("data", {}).get("id", "")
                # Wait briefly then get results
                await asyncio.sleep(3)
                report = await client.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers={"x-apikey": VIRUSTOTAL_API_KEY},
                )
                if report.status_code == 200:
                    stats = report.json().get("data", {}).get("attributes", {}).get("stats", {})
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
            return CheckResult(
                name="VirusTotal",
                status="warning",
                severity="medium",
                summary="VirusTotal returned an unexpected response.",
                details={"status_code": resp.status_code},
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
        async with httpx.AsyncClient(timeout=15) as client:
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
        w = await asyncio.to_thread(whois.whois, domain)
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
                s.settimeout(10)
                s.connect((hostname, port))
                return s.getpeercert()

        cert = await asyncio.to_thread(_get_cert)
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
        async with httpx.AsyncClient(follow_redirects=False, timeout=15) as client:
            current_url = url
            for _ in range(10):
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
        ip = await asyncio.to_thread(socket.gethostbyname, hostname)
        async with httpx.AsyncClient(timeout=10) as client:
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
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
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
