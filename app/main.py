from contextlib import asynccontextmanager
import asyncio
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

from app.api.v1.router import router as v1_router
from app.logging_config import setup_logging
from app.middleware.audit import audit_pat_middleware
from app.middleware.rate_limit import rate_limit_middleware

logger = setup_logging()


async def periodic_cleanup(interval_seconds: int = 3600):
    """
    Run cleanup tasks periodically in the background.

    This function runs in an infinite loop, cleaning up expired upload sessions
    and orphaned temporary files at the specified interval.

    Args:
        interval_seconds: How often to run cleanup (default: 1 hour)

    Note:
        - A fresh database session is created for each cleanup run
        - Errors are logged but don't stop the periodic task
        - The task should be cancelled during application shutdown
    """
    from app.services.cleanup import cleanup_expired_upload_sessions, cleanup_orphaned_temp_files
    from app.database import SessionLocal
    from app.dependencies.storage import get_storage

    logger.info(f"Starting periodic cleanup task (interval: {interval_seconds}s)")

    while True:
        db = None
        try:
            # Create fresh database session for each cleanup run
            db = SessionLocal()
            storage = get_storage()

            try:
                # Clean expired upload sessions
                logger.info("Running cleanup_expired_upload_sessions...")
                await cleanup_expired_upload_sessions(db=db, storage=storage)

                # Clean orphaned temporary files
                logger.info("Running cleanup_orphaned_temp_files...")
                await cleanup_orphaned_temp_files(db=db, storage=storage)

                logger.info("Periodic cleanup completed successfully")

            finally:
                # Always close the database session
                if db is not None:
                    db.close()

        except Exception as e:
            logger.error(f"Periodic cleanup failed: {e}", exc_info=True)
            # Continue running despite errors (don't break the loop)

        # Wait for next interval
        await asyncio.sleep(interval_seconds)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manage application lifecycle events.

    Startup:
    - Start periodic cleanup task to clean expired upload sessions

    Shutdown:
    - Cancel periodic cleanup task gracefully
    """
    # Startup: Start background cleanup task
    cleanup_task = None
    try:
        cleanup_task = asyncio.create_task(periodic_cleanup())
        logger.info("Application startup: cleanup task started")
        yield
    finally:
        # Shutdown: Gracefully cancel cleanup task
        if cleanup_task and not cleanup_task.done():
            logger.info("Application shutdown: cancelling cleanup task...")
            cleanup_task.cancel()
            try:
                await cleanup_task
            except asyncio.CancelledError:
                logger.info("Cleanup task cancelled successfully")


# Create FastAPI app with lifespan management
app = FastAPI(
    title="PAT Auth API",
    description="Personal Access Token authentication with scoped permissions",
    version="1.0.0",
    lifespan=lifespan,
)

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
            "error": "Unauthorized" if exc.status_code == 401 else "Error",
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
