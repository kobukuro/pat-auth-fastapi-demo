from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

from app.api.v1.router import router as v1_router
from app.logging_config import setup_logging
from app.middleware.audit import audit_pat_middleware
from app.middleware.rate_limit import rate_limit_middleware

app = FastAPI(title="PAT Auth API")

# Rate limit must run FIRST
app.middleware("http")(rate_limit_middleware)
# Then audit middleware
app.middleware("http")(audit_pat_middleware)

app.include_router(v1_router, prefix="/api/v1")

# Setup application logging
logger = setup_logging()


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Unwrap the 'detail' field from HTTPException responses."""
    content = exc.detail

    if isinstance(content, dict):
        return JSONResponse(
            status_code=exc.status_code,
            content=content
        )

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": "Error",
            "message": content
        }
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Log detailed error for debugging (includes stack trace)
    logger.error(
        f"Unhandled exception: {exc.__class__.__name__}: {str(exc)}",
        exc_info=True,
        extra={
            "path": request.url.path,
            "method": request.method,
        },
    )

    # Return safe, static message to client (no internal details exposed)
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": "Internal Server Error",
            "message": "An unexpected error occurred",
        },
    )
