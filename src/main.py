"""
msp-push-relay — Push notification relay for MySecurePrint iOS app.

Holds the APNs key centrally so customer-hosted mysecureprint-server instances
can send iOS push notifications without having access to the APNs private key.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
import jwt
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("msp-push-relay")

# ---------------------------------------------------------------------------
# Config from env
# ---------------------------------------------------------------------------
APNS_KEY_ID: str = os.environ.get("APNS_KEY_ID", "")
APNS_TEAM_ID: str = os.environ.get("APNS_TEAM_ID", "")
APNS_PRIVATE_KEY: str = os.environ.get("APNS_PRIVATE_KEY", "")
PORT: int = int(os.environ.get("PORT", "8080"))
BUNDLE_ID: str = "de.nimtz.mysecureprint"
DB_PATH: str = os.environ.get("DB_PATH", "/home/relay.db")

# APNs endpoints
APNS_PROD_HOST = "https://api.push.apple.com"
APNS_SANDBOX_HOST = "https://api.sandbox.push.apple.com"

# Rate limiting: max 5 registrations per IP per hour
RATE_LIMIT_MAX = 5
RATE_LIMIT_WINDOW = 3600  # seconds

# JWT cache: reuse APNs JWT for up to 50 minutes
APNS_JWT_MAX_AGE = 50 * 60  # seconds

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(title="msp-push-relay", version="0.1.0")

# ---------------------------------------------------------------------------
# SQLite setup
# ---------------------------------------------------------------------------
_db_lock = threading.Lock()
_db_conn: sqlite3.Connection | None = None


def get_db() -> sqlite3.Connection:
    global _db_conn
    if _db_conn is None:
        # Ensure directory exists
        db_dir = os.path.dirname(DB_PATH)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        _db_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _db_conn.row_factory = sqlite3.Row
    return _db_conn


def init_db() -> None:
    with _db_lock:
        conn = get_db()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS relay_tokens (
                token       TEXT PRIMARY KEY,
                instance_url TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                last_used   TEXT
            )
        """)
        conn.commit()
    log.info("Database initialised at %s", DB_PATH)


# ---------------------------------------------------------------------------
# Rate limiting (in-memory, per-IP)
# ---------------------------------------------------------------------------
_rate_limit: dict[str, list[float]] = {}
_rate_limit_lock = threading.Lock()


def check_rate_limit(ip: str) -> bool:
    """Returns True if the request is allowed, False if rate-limited."""
    now = time.monotonic()
    cutoff = now - RATE_LIMIT_WINDOW
    with _rate_limit_lock:
        timestamps = _rate_limit.get(ip, [])
        # Prune old entries
        timestamps = [t for t in timestamps if t > cutoff]
        if len(timestamps) >= RATE_LIMIT_MAX:
            _rate_limit[ip] = timestamps
            return False
        timestamps.append(now)
        _rate_limit[ip] = timestamps
        return True


def client_ip(request: Request) -> str:
    """Extract real client IP, honoring X-Forwarded-For from Azure front-end."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------------------
# APNs JWT (cached)
# ---------------------------------------------------------------------------
_apns_token: str | None = None
_apns_token_iat: float = 0.0
_apns_token_lock = threading.Lock()


def get_apns_jwt() -> str:
    """Return a cached APNs JWT, regenerating if older than 50 minutes."""
    global _apns_token, _apns_token_iat
    now = time.monotonic()
    with _apns_token_lock:
        if _apns_token and (now - _apns_token_iat) < APNS_JWT_MAX_AGE:
            return _apns_token

        if not APNS_KEY_ID or not APNS_TEAM_ID or not APNS_PRIVATE_KEY:
            raise RuntimeError(
                "APNs credentials not configured. "
                "Set APNS_KEY_ID, APNS_TEAM_ID, APNS_PRIVATE_KEY env vars."
            )

        iat = int(datetime.now(timezone.utc).timestamp())
        token = jwt.encode(
            payload={"iss": APNS_TEAM_ID, "iat": iat},
            key=APNS_PRIVATE_KEY,
            algorithm="ES256",
            headers={"kid": APNS_KEY_ID},
        )
        _apns_token = token
        _apns_token_iat = now
        log.info("Generated new APNs JWT (kid=%s)", APNS_KEY_ID)
        return _apns_token


# ---------------------------------------------------------------------------
# APNs HTTP/2 client (module-level, lazily initialised)
# ---------------------------------------------------------------------------
_apns_client_prod: httpx.AsyncClient | None = None
_apns_client_sandbox: httpx.AsyncClient | None = None


def get_apns_client(environment: str) -> httpx.AsyncClient:
    global _apns_client_prod, _apns_client_sandbox
    if environment == "sandbox":
        if _apns_client_sandbox is None:
            _apns_client_sandbox = httpx.AsyncClient(
                base_url=APNS_SANDBOX_HOST,
                http2=True,
            )
        return _apns_client_sandbox
    else:
        if _apns_client_prod is None:
            _apns_client_prod = httpx.AsyncClient(
                base_url=APNS_PROD_HOST,
                http2=True,
            )
        return _apns_client_prod


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    instance_url: HttpUrl


class RegisterResponse(BaseModel):
    relay_token: str


class NotifyRequest(BaseModel):
    device_token: str
    title: str
    body: str
    data: dict[str, Any] = {}
    environment: str = "production"  # "production" | "sandbox"
    collapse_id: str | None = None


class NotifyResponse(BaseModel):
    ok: bool


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------
def require_relay_token(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = auth[len("Bearer "):]
    if not token:
        raise HTTPException(status_code=401, detail="Empty relay token")
    return token


# ---------------------------------------------------------------------------
# Startup / shutdown
# ---------------------------------------------------------------------------
@app.on_event("startup")
async def startup() -> None:
    init_db()
    log.info("msp-push-relay started (bundle_id=%s)", BUNDLE_ID)
    if not APNS_KEY_ID:
        log.warning("APNS_KEY_ID not set — APNs calls will fail")
    if not APNS_TEAM_ID:
        log.warning("APNS_TEAM_ID not set — APNs calls will fail")
    if not APNS_PRIVATE_KEY:
        log.warning("APNS_PRIVATE_KEY not set — APNs calls will fail")


@app.on_event("shutdown")
async def shutdown() -> None:
    global _apns_client_prod, _apns_client_sandbox
    for client in (_apns_client_prod, _apns_client_sandbox):
        if client:
            await client.aclose()
    log.info("msp-push-relay shut down")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/health")
async def health() -> dict:
    return {"ok": True, "relay": "msp-push-relay"}


@app.post("/api/register", response_model=RegisterResponse)
async def register(request: Request, body: RegisterRequest) -> RegisterResponse:
    ip = client_ip(request)
    if not check_rate_limit(ip):
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Max 5 registrations per IP per hour.",
        )

    token = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    instance_url = str(body.instance_url)

    with _db_lock:
        conn = get_db()
        conn.execute(
            "INSERT INTO relay_tokens (token, instance_url, created_at, last_used) VALUES (?, ?, ?, NULL)",
            (token, instance_url, now),
        )
        conn.commit()

    log.info("Registered new relay token for instance_url=%s from IP=%s", instance_url, ip)
    return RegisterResponse(relay_token=token)


@app.post("/api/notify", response_model=NotifyResponse)
async def notify(
    request: Request,
    body: NotifyRequest,
    relay_token: str = Depends(require_relay_token),
) -> NotifyResponse:
    # Validate token
    with _db_lock:
        conn = get_db()
        row = conn.execute(
            "SELECT token FROM relay_tokens WHERE token = ?", (relay_token,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Invalid relay token")

        # Update last_used
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "UPDATE relay_tokens SET last_used = ? WHERE token = ?", (now, relay_token)
        )
        conn.commit()

    # Validate environment
    if body.environment not in ("production", "sandbox"):
        raise HTTPException(
            status_code=400,
            detail="environment must be 'production' or 'sandbox'",
        )

    # Build APNs payload
    aps_payload: dict[str, Any] = {
        "aps": {
            "alert": {"title": body.title, "body": body.body},
            "sound": "default",
        }
    }
    # Merge extra data fields at top level (not inside aps)
    for k, v in body.data.items():
        if k != "aps":
            aps_payload[k] = v

    # Build headers
    try:
        jwt_token = get_apns_jwt()
    except RuntimeError as e:
        log.error("APNs JWT error: %s", e)
        raise HTTPException(status_code=503, detail="APNs not configured on relay server")

    headers: dict[str, str] = {
        "authorization": f"bearer {jwt_token}",
        "apns-topic": BUNDLE_ID,
        "apns-push-type": "alert",
        "apns-priority": "10",
    }
    if body.collapse_id:
        headers["apns-collapse-id"] = body.collapse_id

    # Send via APNs HTTP/2
    device_token = body.device_token.strip()
    path = f"/3/device/{device_token}"
    client = get_apns_client(body.environment)

    try:
        response = await client.post(path, json=aps_payload, headers=headers)
    except Exception as e:
        log.error("APNs HTTP error for device=%s: %s", device_token[:8] + "...", e)
        raise HTTPException(status_code=502, detail=f"APNs request failed: {e}")

    if response.status_code == 200:
        log.info(
            "Push sent OK (env=%s, device=%s...)",
            body.environment,
            device_token[:8],
        )
        return NotifyResponse(ok=True)

    # APNs error response
    try:
        apns_error = response.json()
        reason = apns_error.get("reason", "unknown")
    except Exception:
        reason = response.text or "unknown"

    log.warning(
        "APNs rejected push (status=%d, reason=%s, device=%s...)",
        response.status_code,
        reason,
        device_token[:8],
    )

    # Map common APNs status codes to HTTP equivalents
    if response.status_code == 400:
        raise HTTPException(status_code=400, detail=f"APNs bad request: {reason}")
    if response.status_code == 403:
        raise HTTPException(status_code=403, detail=f"APNs auth error: {reason}")
    if response.status_code == 410:
        raise HTTPException(status_code=410, detail=f"Device token no longer active: {reason}")

    raise HTTPException(
        status_code=502,
        detail=f"APNs error {response.status_code}: {reason}",
    )
