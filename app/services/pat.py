import hashlib
import secrets

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.pat import PersonalAccessToken
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


def has_permission_with_granting_scope(
    db: Session, granted_scopes: list[Scope], required_scope: str
) -> tuple[bool, str | None]:
    """
    Check permission and return (has_permission, granting_scope_name).

    This is an optimized version of has_permission() that also returns
    which scope granted access, avoiding duplicate database queries.

    Args:
        db: Database session
        granted_scopes: List of Scope objects the user has
        required_scope: The scope being checked (e.g., "workspaces:read")

    Returns:
        tuple of (has_permission, granting_scope_name):
        - (True, scope_name) if permission granted
        - (False, None) if permission denied
    """
    required = db.execute(select(Scope).where(Scope.name == required_scope)).scalar_one_or_none()
    if not required:
        return False, None

    # Find the best granting scope (same resource, highest level >= required level)
    best_level: int | None = None
    best_name: str | None = None
    for granted in granted_scopes:
        if granted.resource == required.resource and granted.level >= required.level:
            if (
                best_level is None
                or granted.level > best_level
                or (granted.level == best_level and (best_name is None or granted.name > best_name))
            ):
                best_level = granted.level
                best_name = granted.name

    # Return highest level granting scope (matching previous tuple-sort behavior)
    if best_name is not None:
        return True, best_name

    return False, None


def get_pat_by_token(db: Session, token: str) -> PersonalAccessToken | None:
    """
    Lookup PAT by token using indexed prefix with hash filter.

    Query strategy:
    - Use token_prefix (indexed) for fast lookup: O(log n)
    - Filter by token_hash in SQL to get exact match: O(k) where k is candidates
    - Single query returning 0 or 1 record, no memory overhead

    Args:
        db: Database session
        token: Full token string (47 chars, starts with "pat_")

    Returns:
        PersonalAccessToken record if found, None otherwise

    Security:
        - token_prefix reduces search space using index
        - token_hash filter prevents prefix collision attacks
        - SQL-level filtering avoids memory issues

    Performance:
        - token_prefix has index → O(log n) lookup
        - token_hash has NO index but filters small candidate set
        - Typically k=0 or k=1, so hash filter is effectively O(1)
    """
    # Early validation: check token format before querying database
    if not token or len(token) < 8 or not token.startswith("pat_"):
        return None

    # Extract prefix (first 8 chars: "pat_xxxx")
    token_prefix = token[:8]

    # Calculate hash for verification
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    # Single query: indexed prefix + hash filter
    pat = db.execute(
        select(PersonalAccessToken).where(
            PersonalAccessToken.token_prefix == token_prefix,
            PersonalAccessToken.token_hash == token_hash,
        )
    ).scalar_one_or_none()

    return pat
