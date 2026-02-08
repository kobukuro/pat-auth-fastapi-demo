import hashlib
from datetime import datetime, timezone

from fastapi import Request
from sqlalchemy import select

from app.database import SessionLocal
from app.models.audit_log import PersonalAccessTokenAuditLog
from app.models.pat import PersonalAccessToken
from app.utils.datetime import ensure_aware


async def audit_pat_middleware(request: Request, call_next):
    """
    Middleware to audit Personal Access Token usage.

    Logs all requests authenticated with PATs, including successful and
    failed authorization attempts. Updates last_used_at for authorized tokens.

    Non-blocking: logging failures don't break the request.
    """
    # Get authorization header
    auth_header = request.headers.get("Authorization", "")
    token_str = None

    if auth_header.startswith("Bearer "):
        token_str = auth_header[7:]

    # Check if this is a PAT request
    is_pat = token_str and token_str.startswith("pat_")

    # Get client IP
    ip_address = request.client.host if request.client else "unknown"

    # Get request details
    method = request.method
    # Build full path with query string
    path = request.url.path
    if request.url.query:
        path = f"{path}?{request.url.query}"
    endpoint = path

    # Process the request first
    response = await call_next(request)

    # After request completes, log if it was a PAT
    if is_pat:
        # Use separate DB session to avoid interfering with the request
        db = SessionLocal()

        try:
            # Find token by indexed prefix with hash verification
            from app.services.pat import get_pat_by_token

            pat = get_pat_by_token(db, token_str)

            # Only log if token exists in our database (we need token_id)
            if pat:
                # Determine authorization status and reason
                authorized = False
                reason = None

                # Check token validity first
                if pat.is_revoked:
                    reason = "Token has been revoked"
                elif ensure_aware(pat.expires_at) < datetime.now(timezone.utc):
                    reason = "Token has expired"
                else:
                    pat.last_used_at = datetime.now(timezone.utc)
                    # Token is valid, check actual authorization result from response
                    if 200 <= response.status_code < 300:
                        authorized = True
                    elif response.status_code == 401:
                        reason = "Unauthorized"
                    elif response.status_code == 403:
                        reason = "Insufficient permissions"
                    elif 400 <= response.status_code < 500:
                        reason = f"Client error ({response.status_code})"
                    elif response.status_code >= 500:
                        reason = f"Server error ({response.status_code})"
                    else:
                        reason = f"Request failed with status {response.status_code}"

                # Create audit log entry
                log_entry = PersonalAccessTokenAuditLog(
                    token_id=pat.id,
                    timestamp=datetime.now(timezone.utc),
                    ip_address=ip_address,
                    method=method,
                    endpoint=endpoint,
                    status_code=response.status_code,
                    authorized=authorized,
                    reason=reason,
                )
                db.add(log_entry)
                db.commit()

        except Exception as e:
            # Non-blocking: don't let logging failures break the request
            db.rollback()
            # In production, you'd want to log this error somewhere
            print(f"Audit logging failed: {e}")
        finally:
            db.close()

    return response
