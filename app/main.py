from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

from app.api.v1.router import router as v1_router
from app.logging_config import setup_logging
from app.middleware.audit import audit_pat_middleware
from app.middleware.rate_limit import rate_limit_middleware

# title參數: 設定 API的標題名稱，會顯示在：
#   - 自動生成的 API 文件（Swagger UI /docs）
#   - ReDoc 文件（/redoc）
#   - OpenAPI schema 中
app = FastAPI(title="PAT Auth API")

# Rate limit must run FIRST
# 參數 "http" 表示這是 HTTP 中介軟體（會處理每個HTTP請求/回應）
# 下方寫法等於:
# 使用裝飾器語法
#   @app.middleware("http")
#   async def rate_limit_middleware(request: Request, call_next):
#       pass
app.middleware("http")(rate_limit_middleware)
# Then audit middleware
app.middleware("http")(audit_pat_middleware)

# prefix參數設定URL路徑前綴，所有透過v1_router定義的endpoint都會加上這個前綴
app.include_router(v1_router, prefix="/api/v1")

# Setup application logging
logger = setup_logging()


# 這是一個自定義的HTTP例外處理器，用來統一處理FastAPI拋出的HTTPException
# 告訴FastAPI：「當任何地方拋出HTTPException時，呼叫下面的function」
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
        exc_info=True,  # 告訴logger「把完整的錯誤堆疊都記錄下來」，可以知道錯誤發生在哪裡
        # 添加自訂欄位到日誌中, 可以幫助我們在日誌中快速定位是哪個API路徑和HTTP方法發生錯誤
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
