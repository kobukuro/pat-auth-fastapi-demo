from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.api.v1.router import router as v1_router
from app.logging_config import setup_logging
from app.middleware.audit import audit_pat_middleware

app = FastAPI(title="PAT Auth API")

app.middleware("http")(audit_pat_middleware)

app.include_router(v1_router, prefix="/api/v1")

# Setup application logging
logger = setup_logging()


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
