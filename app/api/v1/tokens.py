from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies.auth import get_current_user
from app.dependencies.token import get_validated_token
from app.models.audit_log import PersonalAccessTokenAuditLog
from app.models.pat import PersonalAccessToken
from app.models.user import User
from app.schemas.audit_log import AuditLogEntry, TokenAuditLogsResponse
from app.schemas.common import APIResponse
from app.schemas.pat import PATCreateRequest, PATCreateResponse, PATListItemResponse
from app.services.pat import generate_pat, validate_scopes, get_scopes_by_names

router = APIRouter(prefix="/tokens", tags=["tokens"])


@router.post(
    "",
    response_model=APIResponse[PATCreateResponse],
    status_code=status.HTTP_201_CREATED,
)
def create_token(
        request: PATCreateRequest,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    # Validate scopes exist in DB
    if not validate_scopes(db, request.scopes):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "error": "Bad Request",
                "message": "Invalid scopes",
            },
        )

    # Generate token
    full_token, prefix, token_hash = generate_pat()
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=request.expires_in_days)

    # Get Scope objects
    scope_objects = get_scopes_by_names(db, request.scopes)

    # Create PAT record
    pat = PersonalAccessToken(
        user_id=current_user.id,
        name=request.name,
        token_prefix=prefix,
        token_hash=token_hash,
        scopes=scope_objects,
        created_at=now,
        expires_at=expires_at,
    )
    db.add(pat)
    db.commit()
    db.refresh(pat)

    return APIResponse(
        success=True,
        data=PATCreateResponse(
            id=pat.id,
            name=pat.name,
            token=full_token,
            scopes=request.scopes,
            created_at=pat.created_at,
            expires_at=pat.expires_at,
        ),
    )


@router.get(
    "",
    response_model=APIResponse[list[PATListItemResponse]],
    status_code=status.HTTP_200_OK,
)
def list_tokens(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
):
    """List all PATs belonging to the authenticated user."""
    stmt = select(PersonalAccessToken).where(
        PersonalAccessToken.user_id == current_user.id
    ).order_by(PersonalAccessToken.created_at.desc())

    tokens = db.execute(stmt).scalars().all()

    token_list = [
        PATListItemResponse(
            id=token.id,
            name=token.name,
            token_prefix=token.token_prefix,
            scopes=[scope.name for scope in token.scopes],
            created_at=token.created_at,
            expires_at=token.expires_at,
            last_used_at=token.last_used_at,
            is_revoked=token.is_revoked,
        )
        for token in tokens
    ]

    return APIResponse(success=True, data=token_list)


@router.get(
    "/{token_id}",
    response_model=APIResponse[PATListItemResponse],
    status_code=status.HTTP_200_OK,
)
def get_token(
        token: PersonalAccessToken = Depends(get_validated_token),
):
    """Get a single PAT by ID."""
    return APIResponse(
        success=True,
        data=PATListItemResponse(
            id=token.id,
            name=token.name,
            token_prefix=token.token_prefix,
            scopes=[scope.name for scope in token.scopes],
            created_at=token.created_at,
            expires_at=token.expires_at,
            last_used_at=token.last_used_at,
            is_revoked=token.is_revoked,
        ),
    )


@router.delete(
    "/{token_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def revoke_token(
        token: PersonalAccessToken = Depends(get_validated_token),
        db: Session = Depends(get_db),
):
    """Revoke a PAT by ID (soft delete)."""
    token.is_revoked = True
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/{token_id}/logs",
    response_model=APIResponse[TokenAuditLogsResponse],
    status_code=status.HTTP_200_OK,
)
def get_token_logs(
        token: PersonalAccessToken = Depends(get_validated_token),
        db: Session = Depends(get_db),
):
    """Get audit logs for a specific PAT."""
    # Query audit logs for this token
    logs_stmt = select(PersonalAccessTokenAuditLog).where(
        PersonalAccessTokenAuditLog.token_id == token.id
    ).order_by(PersonalAccessTokenAuditLog.timestamp.desc())

    logs = db.execute(logs_stmt).scalars().all()

    # Convert to response format
    log_entries = []
    for log in logs:
        entry_data = {
            "timestamp": log.timestamp,
            "ip_address": log.ip_address,
            "method": log.method,
            "endpoint": log.endpoint,
            "status_code": log.status_code,
            "authorized": log.authorized,
        }
        # Only include reason for unauthorized requests
        if not log.authorized:
            entry_data["reason"] = log.reason
        log_entries.append(AuditLogEntry(**entry_data))

    return APIResponse(
        success=True,
        data=TokenAuditLogsResponse(
            token_id=str(token.id),
            token_name=token.name,
            total_logs=len(log_entries),
            logs=log_entries,
        ),
    )
