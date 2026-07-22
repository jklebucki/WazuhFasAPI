"""Structured request logging without secrets or response bodies."""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from datetime import UTC, datetime

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
DEFAULT_CSP = "default-src 'none'"
DOCS_CSP = (
    "default-src 'none'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data: https://fastapi.tiangolo.com; "
    "connect-src 'self'"
)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        for field in (
            "request_id",
            "method",
            "path",
            "status_code",
            "duration_ms",
            "client_ip",
            "upstream_status",
        ):
            payload[field] = getattr(record, field, None)
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())


class RequestMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        supplied = request.headers.get("X-Request-ID", "")
        request_id = supplied if REQUEST_ID_RE.fullmatch(supplied) else str(uuid.uuid4())
        request.state.request_id = request_id
        started = time.perf_counter()
        response = await call_next(request)
        duration = round((time.perf_counter() - started) * 1000, 2)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        is_docs_ui = request.url.path == "/redoc" or request.url.path.startswith("/docs")
        response.headers["Content-Security-Policy"] = DOCS_CSP if is_docs_ui else DEFAULT_CSP
        if "Cache-Control" not in response.headers:
            response.headers["Cache-Control"] = "no-store"
        logging.getLogger("wazuh_bootstrap.access").info(
            "request completed",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": duration,
                "client_ip": request.client.host if request.client else None,
                "upstream_status": getattr(request.state, "upstream_status", None),
            },
        )
        return response
