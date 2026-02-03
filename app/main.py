from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.api.v1.router import router as v1_router
from app.middleware.audit import audit_pat_middleware

app = FastAPI(title="PAT Auth API")

app.middleware("http")(audit_pat_middleware)

app.include_router(v1_router, prefix="/api/v1")


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"success": False, "error": "Internal Server Error", "message": str(exc)},
    )
