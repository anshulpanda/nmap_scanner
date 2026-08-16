"""Application entry point: create the app, wire routes, serve static files."""

import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.exc import OperationalError

from app.database import init_db
from app.routes import router

BASE_DIR = Path(__file__).resolve().parent.parent

# A dedicated logger + handler, rather than relying on root logging config:
# uvicorn's default logging setup only configures its own "uvicorn.*"
# loggers, not the root logger, so an access log that only propagated
# upward would silently print nothing under a plain `uvicorn` run.
access_logger = logging.getLogger("app.access")
access_logger.setLevel(logging.INFO)
if not access_logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(asctime)s %(message)s", "%Y-%m-%d %H:%M:%S"))
    access_logger.addHandler(_handler)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Creates the tables if they don't exist. At this scope a migration tool
    # would be more machinery than the schema warrants.
    init_db()
    yield


app = FastAPI(
    title="NMAP Port Scanner",
    description="Scan a host for open ports (0-1000), track changes over time.",
    version="1.0.0",
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
app.include_router(router)


@app.middleware("http")
async def log_access(request: Request, call_next):
    """One line per response: method, path, status, and how long it took.

    Wrapped in try/finally so a genuinely unhandled exception (which
    propagates through call_next rather than returning a response) still
    gets logged, with status 500, instead of silently skipping the log line.
    """
    start = time.perf_counter()
    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        duration_ms = (time.perf_counter() - start) * 1000
        access_logger.info(
            "%s %s -> %s (%.1fms)",
            request.method,
            request.url.path,
            status_code,
            duration_ms,
        )


@app.exception_handler(RequestValidationError)
async def malformed_request_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Answer malformed requests with 400, matching invalid-host errors.

    FastAPI's default is 422. Deliberate choice: from a caller's point of view
    "you sent no target" and "your target is nonsense" are the same class of
    mistake, so they get the same status and the same {"detail": "..."} shape.
    """
    first = exc.errors()[0]
    field = ".".join(str(part) for part in first["loc"] if part != "body")
    message = f"{field}: {first['msg']}" if field else first["msg"]
    return JSONResponse(status_code=400, content={"detail": f"Invalid request. {message}"})


@app.exception_handler(OperationalError)
async def database_unavailable_handler(
    request: Request, exc: OperationalError
) -> JSONResponse:
    """Turn a DB connection failure into a clean 503, not a bare 500.

    Every other failure mode in this app has a purpose-built response shape
    (400 + detail for bad input, ok/error per target for scan failures); a
    database outage was the one gap, falling through to Starlette's generic,
    JSON-less 500. OperationalError specifically covers connection-level
    failures (unreachable server, lost connection, timeout) via
    pool_pre_ping's reconnect attempt — not query bugs like a constraint
    violation, which should still surface as an unhandled error rather than
    being reported to the caller as "try again shortly".
    """
    access_logger.error("Database unavailable: %s", exc)
    return JSONResponse(
        status_code=503,
        content={"detail": "Database is unavailable. Please try again shortly."},
    )
