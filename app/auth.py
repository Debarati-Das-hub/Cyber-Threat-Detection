"""
Authentication & API Security Middleware
Resolves Gap #6: API Key validation, bearer token support, configurable enforcement, and rate tracking.
"""

from __future__ import annotations
import os
import time
from typing import Dict, Optional
from fastapi import Header, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

CONFIGURED_API_KEY = os.getenv("API_KEY", "cyber-sec-demo-key-2026").strip()
REQUIRE_AUTH = os.getenv("REQUIRE_API_KEY", "false").lower() in ("true", "1", "yes")

# In-memory IP rate limiter for basic DDoS / flood protection
REQUEST_COUNTS: Dict[str, list] = {}
RATE_LIMIT_WINDOW_SEC = 60
RATE_LIMIT_MAX_REQUESTS = 120


def verify_api_key(
    request: Request,
    x_api_key: Optional[str] = Security(API_KEY_HEADER),
    authorization: Optional[str] = Header(None)
) -> bool:
    """
    Validates API key from either 'X-API-Key' header or 'Authorization: Bearer <key>'.
    Enforces check if REQUIRE_API_KEY=true.
    """
    # 1. Rate limiting check
    client_ip = request.client.host if request.client else "127.0.0.1"
    now = time.time()
    history = REQUEST_COUNTS.setdefault(client_ip, [])
    # Prune old timestamps
    history[:] = [t for t in history if now - t < RATE_LIMIT_WINDOW_SEC]
    if len(history) >= RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Maximum 120 requests per minute allowed."
        )
    history.append(now)

    # If auth requirement is disabled for local demo convenience, allow
    if not REQUIRE_AUTH:
        return True

    # Check X-API-Key header
    if x_api_key and x_api_key == CONFIGURED_API_KEY:
        return True

    # Check Authorization: Bearer <key>
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ", 1)[1].strip()
        if token == CONFIGURED_API_KEY:
            return True

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized. A valid 'X-API-Key' or 'Authorization: Bearer <token>' header is required.",
        headers={"WWW-Authenticate": "ApiKey"},
    )
