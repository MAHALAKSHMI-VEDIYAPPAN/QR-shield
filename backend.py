"""
QR Code Threat Intelligence Analyzer - FastAPI Backend
=======================================================
Run: uvicorn backend:app --reload --host 0.0.0.0 --port 8000
Docs: http://localhost:8000/docs
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import ssl
import socket
import urllib.request
import urllib.parse
import re
import json
import hashlib
from datetime import datetime, timedelta
import httpx

# ──────────────────────────────────────────────
#  APP SETUP
# ──────────────────────────────────────────────
app = FastAPI(
    title="QR Threat Intelligence Analyzer API",
    description="Backend API for QR code security analysis",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──────────────────────────────────────────────
#  MODELS
# ──────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    url: str
    deep_scan: bool = False

class CheckResult(BaseModel):
    name: str
    value: str
    detail: str
    status: str          # "pass" | "warn" | "fail"
    icon: str

class AnalyzeResponse(BaseModel):
    url: str
    score: int
    risk_level: str      # "safe" | "warn" | "danger"
    checks: list[CheckResult]
    redirect_chain: list[str]
    tags: list[str]
    timestamp: str
    summary: str

# ──────────────────────────────────────────────
#  HELPERS
# ──────────────────────────────────────────────

PHISHING_KEYWORDS = [
    "paypa1", "g00gle", "amaz0n", "faceb00k", "apple-verify",
    "bank-login", "secure-update", "account-suspended", "signin-verify",
    "verify-account", "unusual-activity", "update-payment"
]

SUSPICIOUS_TLDs = [".xyz", ".tk", ".ml", ".ga", ".cf", ".ru", ".cn"]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "short.link", "rebrand.ly", "cutt.ly"
]

SUSPICIOUS_PARAMS = [
    "steal", "phish", "password", "verify", "confirm",
    "suspend", "token", "bank", "credential", "login"
]


def extract_domain(url: str) -> str:
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return url.lower()


def check_ssl(url: str) -> CheckResult:
    """Verify SSL certificate for HTTPS URLs."""
    if not url.startswith("https://"):
        return CheckResult(
            name="SSL Certificate",
            value="No HTTPS",
            detail="Connection is unencrypted (HTTP)",
            status="fail",
            icon="🔓"
        )
    try:
        domain = extract_domain(url)
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.utcnow()).days
                if days_left < 30:
                    return CheckResult(
                        name="SSL Certificate",
                        value=f"Expires in {days_left} days",
                        detail="Certificate near expiry — risky",
                        status="warn",
                        icon="🔒"
                    )
                return CheckResult(
                    name="SSL Certificate",
                    value="Valid",
                    detail=f"Expires in {days_left} days",
                    status="pass",
                    icon="🔒"
                )
    except ssl.SSLCertVerificationError:
        return CheckResult(
            name="SSL Certificate",
            value="Invalid Certificate",
            detail="SSL verification failed",
            status="fail",
            icon="⚠️"
        )
    except Exception as e:
        return CheckResult(
            name="SSL Certificate",
            value="Check Failed",
            detail=str(e)[:60],
            status="warn",
            icon="🔒"
        )


def check_redirects(url: str) -> tuple[list[str], CheckResult]:
    """Trace redirect chain up to 5 hops."""
    chain = [url]
    current = url
    try:
        for _ in range(5):
            req = urllib.request.Request(
                current,
                headers={"User-Agent": "Mozilla/5.0 QRThreatAnalyzer/1.0"},
                method="HEAD"
            )
            resp = urllib.request.urlopen(req, timeout=5)
            final = resp.url
            if final == current:
                break
            chain.append(final)
            current = final
    except Exception:
        pass

    has_shortener = any(s in url.lower() for s in URL_SHORTENERS)
    hops = len(chain) - 1

    if hops >= 3 or has_shortener:
        result = CheckResult(
            name="Redirect Chain",
            value=f"{hops} redirect(s)",
            detail="URL shortener or long redirect chain",
            status="warn",
            icon="🔗"
        )
    elif hops > 0:
        result = CheckResult(
            name="Redirect Chain",
            value=f"{hops} redirect(s)",
            detail="Minor redirects detected",
            status="warn",
            icon="🔗"
        )
    else:
        result = CheckResult(
            name="Redirect Chain",
            value="Direct link",
            detail="No redirects",
            status="pass",
            icon="🔗"
        )
    return chain, result


def check_domain_patterns(url: str, domain: str) -> tuple[int, list[CheckResult], list[str]]:
    """Check typosquatting, suspicious TLDs, raw IPs, bad params."""
    score = 0
    checks = []
    tags = []
    lower = url.lower()

    # Typosquatting
    is_typo = any(p in lower for p in PHISHING_KEYWORDS)
    if is_typo:
        score += 35
        tags += ["Typosquatting", "Phishing"]
        checks.append(CheckResult(
            name="Typosquatting",
            value="Detected",
            detail="URL mimics a legitimate brand",
            status="fail",
            icon="🎭"
        ))
    else:
        checks.append(CheckResult(
            name="Typosquatting",
            value="Not Detected",
            detail="No brand impersonation patterns",
            status="pass",
            icon="🎭"
        ))

    # Suspicious TLD
    is_bad_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDs)
    if is_bad_tld:
        score += 15
        tags.append("Suspicious TLD")
        checks.append(CheckResult(
            name="Domain TLD",
            value="High-Risk TLD",
            detail="TLD commonly used for abuse",
            status="fail",
            icon="🌐"
        ))
    else:
        checks.append(CheckResult(
            name="Domain TLD",
            value="Normal TLD",
            detail="No TLD-based risk detected",
            status="pass",
            icon="🌐"
        ))

    # Raw IP
    is_ip = bool(re.match(r'\d{1,3}(\.\d{1,3}){3}', domain))
    if is_ip:
        score += 20
        tags.append("Raw IP")
        checks.append(CheckResult(
            name="Domain / IP",
            value="Raw IP Address",
            detail="No domain name — highly suspicious",
            status="fail",
            icon="💻"
        ))
    else:
        checks.append(CheckResult(
            name="Domain / IP",
            value="Valid Domain",
            detail="Domain name registered",
            status="pass",
            icon="💻"
        ))

    # Suspicious params
    has_bad_param = any(p in lower for p in SUSPICIOUS_PARAMS)
    if has_bad_param:
        score += 20
        tags.append("Suspicious Params")
        checks.append(CheckResult(
            name="URL Parameters",
            value="Suspicious",
            detail="Credential/phishing keywords in URL",
            status="fail",
            icon="🔍"
        ))
    else:
        checks.append(CheckResult(
            name="URL Parameters",
            value="Clean",
            detail="No suspicious parameters",
            status="pass",
            icon="🔍"
        ))

    return score, checks, tags


def compute_risk_level(score: int) -> str:
    if score >= 70:
        return "danger"
    elif score >= 35:
        return "warn"
    return "safe"


def build_summary(score: int, risk_level: str, tags: list[str]) -> str:
    if risk_level == "danger":
        return f"HIGH RISK: This URL is likely malicious. Risk score {score}/100. Issues: {', '.join(tags) or 'Multiple threats detected'}."
    elif risk_level == "warn":
        return f"SUSPICIOUS: Proceed with caution. Risk score {score}/100. Concerns: {', '.join(tags) or 'Some suspicious indicators'}."
    return f"SAFE: This URL appears legitimate. Risk score {score}/100. No major threats detected."


# ──────────────────────────────────────────────
#  ROUTES
# ──────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "service": "QR Threat Intelligence Analyzer API",
        "version": "1.0.0",
        "endpoints": ["/analyze", "/health", "/docs"]
    }


@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_url(req: AnalyzeRequest):
    url = req.url.strip()

    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    # Normalize
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    domain = extract_domain(url)
    score = 0
    all_checks: list[CheckResult] = []
    all_tags: list[str] = []

    # 1. SSL
    ssl_check = check_ssl(url)
    all_checks.append(ssl_check)
    if ssl_check.status == "fail":
        score += 25
        all_tags.append("No HTTPS")
    elif ssl_check.status == "warn":
        score += 10

    # 2. Redirects
    redirect_chain, redirect_check = check_redirects(url)
    all_checks.append(redirect_check)
    if redirect_check.status == "warn":
        score += 15
        if any(s in url.lower() for s in URL_SHORTENERS):
            all_tags.append("URL Shortener")
    
    # 3. Domain patterns
    pattern_score, pattern_checks, pattern_tags = check_domain_patterns(url, domain)
    score += pattern_score
    all_checks.extend(pattern_checks)
    all_tags.extend(pattern_tags)

    # 4. Final score
    score = min(100, max(0, score))
    risk_level = compute_risk_level(score)

    return AnalyzeResponse(
        url=url,
        score=score,
        risk_level=risk_level,
        checks=all_checks,
        redirect_chain=redirect_chain,
        tags=list(set(all_tags)),
        timestamp=datetime.utcnow().isoformat(),
        summary=build_summary(score, risk_level, all_tags)
    )


@app.get("/history")
def get_history():
    """In production, connect to a database here."""
    return {"message": "Connect to your database to retrieve scan history."}


# ──────────────────────────────────────────────
#  ENTRYPOINT
# ──────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend:app", host="0.0.0.0", port=8000, reload=True)
