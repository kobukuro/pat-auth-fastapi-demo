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

    # Handle proxy scenarios
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        ip_address = forwarded_for.split(",")[0].strip()

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
