"""
Live Website Security Assessment API for RepoShield V2.
Performs safe, non-destructive external HTTP security posture evaluations
with strict anti-SSRF protections, DNS resolution validation, and authorization controls.
"""
import ipaddress
import socket
import time
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
import httpx
from app.core.security import is_private_ip, DISALLOWED_HOSTS

router = APIRouter(prefix="/api/website-security", tags=["Website Security"])

class WebsiteAssessmentRequest(BaseModel):
    url: str = Field(description="Target public URL to assess e.g. https://example.com")
    authorized: bool = Field(description="Explicit user confirmation of authorization to assess target")

class SecurityHeaderCheck(BaseModel):
    name: str
    status: str  # "PASS", "WARN", "FAIL"
    value: Optional[str] = None
    description: str
    recommendation: str

class CookieCheck(BaseModel):
    name: str
    has_secure: bool
    has_httponly: bool
    samesite: Optional[str] = None
    status: str

class WebsiteAssessmentResult(BaseModel):
    target_url: str
    final_url: str
    ip_address: str
    score: int  # 0 to 100
    grade: str  # A+, A, B, C, D, F
    https_enforced: bool
    headers: List[SecurityHeaderCheck]
    cookies: List[CookieCheck]
    server_banner: Optional[str] = None
    duration_seconds: float
    timestamp: str
    disclaimer: str

def validate_public_destination(url_str: str) -> tuple[str, str]:
    """
    Validates that a URL is well-formed, uses http/https, and resolves ONLY to public IP addresses.
    Strict defense against SSRF, cloud metadata access, and loopback snooping.
    """
    if not url_str or not isinstance(url_str, str):
        raise HTTPException(status_code=400, detail="Target URL is required.")

    parsed = urlparse(url_str.strip())
    if parsed.scheme not in ["http", "https"]:
        raise HTTPException(status_code=400, detail="URL scheme must be either http or https.")

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid target URL: missing hostname.")

    if hostname.lower() in DISALLOWED_HOSTS:
        raise HTTPException(status_code=400, detail="Assessment of internal, loopback, or cloud metadata hosts is strictly prohibited.")

    # DNS Resolution check
    try:
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise HTTPException(status_code=400, detail=f"Failed to resolve hostname: '{hostname}'.")

    resolved_ip = None
    for entry in addr_info:
        ip_cand = entry[4][0]
        if is_private_ip(ip_cand):
            raise HTTPException(status_code=400, detail=f"Host '{hostname}' resolves to a private or restricted IP ({ip_cand}). Access denied.")
        if not resolved_ip:
            resolved_ip = ip_cand

    if not resolved_ip:
        raise HTTPException(status_code=400, detail="No public IP address found for host.")

    return parsed.geturl(), resolved_ip

@router.post("/assess", response_model=WebsiteAssessmentResult)
async def assess_website(request: WebsiteAssessmentRequest):
    """
    Conducts a safe, non-destructive HTTP header, SSL/TLS, and cookie posture audit.
    Requires explicit authorization confirmation.
    """
    if not request.authorized:
        raise HTTPException(
            status_code=400,
            detail="Explicit user confirmation of authorization is mandatory to execute website assessment."
        )

    clean_url, resolved_ip = validate_public_destination(request.url)
    start_time = time.time()
    headers_list: List[SecurityHeaderCheck] = []
    cookies_list: List[CookieCheck] = []
    score = 100
    server_banner = None

    async with httpx.AsyncClient(
        verify=True,
        timeout=15.0,
        follow_redirects=True,
        max_redirects=5,
        headers={"User-Agent": "RepoShield-Security-Auditor/2.0 (Non-Destructive Posture Check)"}
    ) as client:
        try:
            resp = await client.get(clean_url)
        except httpx.RequestError as e:
            raise HTTPException(status_code=502, detail=f"Connection to target host failed: {str(e)[:150]}")

        final_url = str(resp.url)
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        https_enforced = final_url.startswith("https://")

        if not https_enforced:
            score -= 30

        server_banner = resp_headers.get("server")
        if server_banner and any(char.isdigit() for char in server_banner):
            score -= 5

        # 1. Strict-Transport-Security (HSTS)
        hsts = resp_headers.get("strict-transport-security")
        if hsts:
            has_sub = "includesubdomains" in hsts.lower()
            headers_list.append(SecurityHeaderCheck(
                name="Strict-Transport-Security (HSTS)",
                status="PASS",
                value=hsts,
                description="HSTS forces browsers to connect exclusively over HTTPS, mitigating SSL stripping.",
                recommendation="Ensure max-age is at least 31536000 (1 year) and includeSubDomains is set."
            ))
        else:
            score -= 15
            headers_list.append(SecurityHeaderCheck(
                name="Strict-Transport-Security (HSTS)",
                status="FAIL",
                value=None,
                description="Header missing. Browsers may downgrade connections to cleartext HTTP.",
                recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'."
            ))

        # 2. Content-Security-Policy (CSP)
        csp = resp_headers.get("content-security-policy")
        if csp:
            headers_list.append(SecurityHeaderCheck(
                name="Content-Security-Policy (CSP)",
                status="PASS",
                value=csp[:100] + ("..." if len(csp) > 100 else ""),
                description="CSP restricts authorized sources of scripts, styles, and framed content, preventing XSS.",
                recommendation="Review CSP rules to avoid 'unsafe-inline' or 'unsafe-eval'."
            ))
        else:
            score -= 15
            headers_list.append(SecurityHeaderCheck(
                name="Content-Security-Policy (CSP)",
                status="FAIL",
                value=None,
                description="Header missing. Application is more vulnerable to Cross-Site Scripting (XSS).",
                recommendation="Configure a restrictive Content-Security-Policy restricting script-src and object-src."
            ))

        # 3. X-Frame-Options
        xfo = resp_headers.get("x-frame-options")
        if xfo and xfo.upper() in ["DENY", "SAMEORIGIN"]:
            headers_list.append(SecurityHeaderCheck(
                name="X-Frame-Options",
                status="PASS",
                value=xfo,
                description="Prevents clickjacking by controlling whether the site can be framed.",
                recommendation="Maintain DENY or SAMEORIGIN."
            ))
        else:
            score -= 10
            headers_list.append(SecurityHeaderCheck(
                name="X-Frame-Options",
                status="FAIL",
                value=xfo,
                description="Missing or insecurely configured frame protection.",
                recommendation="Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'."
            ))

        # 4. X-Content-Type-Options
        xcto = resp_headers.get("x-content-type-options")
        if xcto and "nosniff" in xcto.lower():
            headers_list.append(SecurityHeaderCheck(
                name="X-Content-Type-Options",
                status="PASS",
                value=xcto,
                description="Prevents MIME type sniffing, mitigating drive-by executable downloads.",
                recommendation="Keep 'X-Content-Type-Options: nosniff'."
            ))
        else:
            score -= 10
            headers_list.append(SecurityHeaderCheck(
                name="X-Content-Type-Options",
                status="FAIL",
                value=xcto,
                description="Header missing. Browsers may sniff responses away from declared Content-Type.",
                recommendation="Set 'X-Content-Type-Options: nosniff'."
            ))

        # 5. Referrer-Policy
        ref_pol = resp_headers.get("referrer-policy")
        if ref_pol:
            headers_list.append(SecurityHeaderCheck(
                name="Referrer-Policy",
                status="PASS",
                value=ref_pol,
                description="Controls how much referrer information is included with requests.",
                recommendation="Set to 'strict-origin-when-cross-origin' or 'no-referrer'."
            ))
        else:
            score -= 5
            headers_list.append(SecurityHeaderCheck(
                name="Referrer-Policy",
                status="WARN",
                value=None,
                description="Missing. May leak sensitive URL query parameters across domain origins.",
                recommendation="Add 'Referrer-Policy: strict-origin-when-cross-origin'."
            ))

        # 6. Cookies audit
        for cookie in resp.cookies.jar:
            sec = cookie.secure
            http_only = cookie.has_nonstandard_attr("httponly") or getattr(cookie, "_rest", {}).get("httponly") is not None
            samesite = getattr(cookie, "_rest", {}).get("samesite")
            c_status = "PASS" if (sec and http_only) else "WARN"
            if not sec:
                score -= 5
            cookies_list.append(CookieCheck(
                name=cookie.name,
                has_secure=sec,
                has_httponly=http_only,
                samesite=samesite,
                status=c_status
            ))

    score = max(0, min(100, score))
    if score >= 90:
        grade = "A+"
    elif score >= 80:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 50:
        grade = "D"
    else:
        grade = "F"

    duration = round(time.time() - start_time, 2)
    return WebsiteAssessmentResult(
        target_url=clean_url,
        final_url=final_url,
        ip_address=resolved_ip,
        score=score,
        grade=grade,
        https_enforced=https_enforced,
        headers=headers_list,
        cookies=cookies_list,
        server_banner=server_banner,
        duration_seconds=duration,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        disclaimer="Non-destructive external configuration audit. Does not constitute a penetration test or guarantee absence of internal vulnerabilities."
    )
