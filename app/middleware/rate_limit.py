from fastapi import Request
from fastapi.responses import JSONResponse

from app.config import settings
from app.rate_limiter import RateLimiter

# Global rate limiter instance
rate_limiter = RateLimiter(
    max_requests=settings.RATE_LIMIT_MAX_REQUESTS,
    window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS
)


async def rate_limit_middleware(request: Request, call_next):
    """
    IP-based rate limiting middleware.

    Checks request count per IP before processing the request.
    Returns 429 Too Many Requests if limit exceeded.
    """
    # Check if rate limiting is enabled
    if not settings.RATE_LIMIT_ENABLED:
        return await call_next(request)

    # Extract IP address (same pattern as audit_pat_middleware)
    ip_address = request.client.host if request.client else "unknown"

    """
    處理反向代理（Reverse Proxy）情境，取得真實客戶端 IP 位址。
    X-Forwarded-For 是一個 HTTP 標頭，用來記錄「請求經過的所有 IP 位址」
    為什麼需要這個？
    當你的網站前面有代理伺服器或負載平衡器時：
    
    真實客戶端 (1.2.3.4)
          ↓
    Nginx 代理伺服器 (10.0.0.5)
          ↓
    FastAPI 應用程式
    
    FastAPI 收到的 request.client.host 會是 Nginx 的 IP (10.0.0.5)，而不是真實客戶端 IP (1.2.3.4)！
    
    X-Forwarded-For 格式
    
    X-Forwarded-For: 1.2.3.4, 10.0.0.5, 10.0.0.6
                       ↑        ↑         ↑
                     真實IP   第1個代理  第2個代理
    
    特點：
    - IP 位址用逗號分隔
    - 從左到右排列：客戶端 → 第一個代理 → 第二個代理...
    - 最左邊是「原始客戶端 IP」
    """
    # Handle proxy scenarios
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        ip_address = forwarded_for.split(",")[0].strip()

    """
    - is_allowed：布林值，表示「是否允許這次請求」
        - True = 沒超過限制，可以放行
        - False = 超過限制，要阻擋
    - retry_after：整數或 None
        - 如果 is_allowed = False：還要等幾秒才能再請求（例如：15 秒）
        - 如果 is_allowed = True：None（不需要等）
    """
    # Check rate limit
    is_allowed, retry_after = await rate_limiter.check_rate_limit(ip_address)

    # Return 429 immediately if over limit
    if not is_allowed:
        return JSONResponse(
            status_code=429,
            content={
                "success": False,
                "error": "Too Many Requests",
                "data": {
                    "retry_after": retry_after
                }
            }
        )

    # Proceed with request
    return await call_next(request)
