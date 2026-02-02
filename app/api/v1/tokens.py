import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies.auth import get_current_user
from app.models.pat import PersonalAccessToken
from app.models.user import User
from app.schemas.common import APIResponse
from app.schemas.pat import PATCreateRequest, PATCreateResponse
from app.services.pat import generate_pat, validate_scopes

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

    # Create PAT record
    pat = PersonalAccessToken(
        user_id=current_user.id,
        name=request.name,
        token_prefix=prefix,
        token_hash=token_hash,
        scopes=json.dumps(request.scopes),
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
