import hashlib
import secrets

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.scope import Scope


def generate_pat() -> tuple[str, str, str]:
    """
    Generate a Personal Access Token.

    Returns:
        tuple: (full_token, prefix, token_hash)
            - full_token: The complete token to return to user (only once)
            - prefix: First 8 chars for lookup
            - token_hash: SHA-256 hash for storage
    """
    random_part = secrets.token_urlsafe(32)
    full_token = f"pat_{random_part}"
    prefix = full_token[:8]
    token_hash = hashlib.sha256(full_token.encode()).hexdigest()
    return full_token, prefix, token_hash


def validate_scopes(db: Session, scope_names: list[str]) -> bool:
    """Validate that all scope names exist in database."""
    if not scope_names:
        return False
    existing = db.execute(select(Scope.name).where(Scope.name.in_(scope_names))).scalars().all()
    return len(existing) == len(scope_names)


def get_scopes_by_names(db: Session, scope_names: list[str]) -> list[Scope]:
    """Retrieve Scope objects by their names."""
    if not scope_names:
        return []
    return list(db.execute(
        select(Scope).where(Scope.name.in_(scope_names))
    ).scalars().all())


def has_permission(db: Session, granted_scopes: list[Scope], required_scope: str) -> bool:
    """
    Check if granted_scopes satisfy required_scope.

    Higher level includes lower level within same resource.
    Does NOT inherit across different resources.
    """
    required = db.execute(select(Scope).where(Scope.name == required_scope)).scalar_one_or_none()
    if not required:
        return False

    for granted in granted_scopes:
        if granted.resource == required.resource and granted.level >= required.level:
            return True

    return False
