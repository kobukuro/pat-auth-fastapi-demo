# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a FastAPI demo project implementing Personal Access Token (PAT) authentication with a hierarchical scope-based authorization system. The architecture demonstrates a two-tier authentication pattern: JWT tokens for user sessions and PATs for API access with fine-grained permissions.

## Commands

### Development
```bash
# Install dependencies (requires UV package manager)
uv sync

# Run development server with auto-reload
uv run uvicorn app.main:app --reload

# Run with hot reload on specific port
uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Docker
```bash
# Start development environment (runs migrations + starts app)
docker compose --profile dev up --build

# Start test environment (runs pytest)
docker compose --profile test up --build

# Clean up volumes
docker compose --profile test down -v
```

### Testing
```bash
# Run all tests
pytest

# Run specific test file
pytest tests/api/test_tokens.py

# Run with verbose output
pytest -v

# Run specific test
pytest tests/api/test_tokens.py::test_create_token
```

### Database Migrations
```bash
# Create a new migration
alembic revision --autogenerate -m "description"

# Apply migrations
alembic upgrade head

# Rollback one migration
alembic downgrade -1

# View migration history
alembic history
```

### Linting
```bash
# Run pre-commit hooks manually
pre-commit run --all-files
```

## Architecture

### Authentication Flow
1. **User Registration/Login** (`app/api/v1/auth.py`) - Users authenticate with email/password, receive JWT token
2. **PAT Creation** (`app/api/v1/tokens.py`) - Users create PATs with specific scopes (e.g., `workspaces:read`)
3. **PAT Validation** (`app/dependencies/pat.py`) - Middleware validates PATs from Authorization header on each request
4. **Authorization** (`app/services/pat.py`) - Scope-based permission checks using hierarchical system

### Key Architectural Patterns

**Two-tier Authentication:**
- JWT tokens: For user session management (login/logout)
- PATs: For API access with scoped permissions, stored as SHA-256 hashes

**Scope System:**
- Hierarchical permissions: `resource:action` format (e.g., `workspaces:read`, `workspaces:write`)
- Permission levels: read(1) < write(2) < delete(3) < admin(4)
- Permission inheritance: Higher-level scopes grant access to lower-level endpoints on the same resource
- Scopes are stored in the database and seeded via Alembic migrations

**Dependency Injection Pattern:**
- `app/dependencies/auth.py` - JWT authentication for user endpoints
- `app/dependencies/pat.py` - PAT validation for API endpoints
- `app/dependencies/token.py` - Token validation utilities
- Use `require_scope("workspaces:read")` to protect endpoints

**Audit Logging:**
- `app/middleware/audit.py` - Logs all PAT usage (endpoint, method, timestamp)
- Captures which scope granted access to each request

### Project Structure
```
app/
├── api/v1/          # API endpoints (auth, tokens, workspaces)
├── config.py        # Pydantic settings (loads from .env)
├── database.py      # SQLAlchemy session management
├── dependencies/    # FastAPI dependency injection for auth
├── middleware/      # HTTP middleware (audit logging)
├── models/          # SQLAlchemy ORM models (User, PAT, Scope, AuditLog)
├── schemas/         # Pydantic schemas for request/response validation
└── services/        # Business logic (auth, JWT, PAT operations)
```

### Environment Setup
1. Copy `.env.sample` to `.env` (create from required vars in `app/config.py`)
2. Required environment variables:
   - `DATABASE_URL` - PostgreSQL connection string
   - `JWT_SECRET_KEY` - Secret for JWT signing
3. PostgreSQL 16+ required (use Docker Compose for local development)

### Testing Notes
- Tests use pytest with FastAPI TestClient
- Database transactions are rolled back after each test (`tests/conftest.py`)
- Scope data is seeded at test session start
- Tests are organized by API endpoint (auth, tokens, workspaces)

### Common Patterns

**Adding a new protected endpoint:**
```python
from app.dependencies.pat import require_scope

@router.get("/api/v1/resources")
async def list_resources(
    auth: AuthContext = Depends(require_scope("resources:read"))
):
    # auth.pat, auth.scopes, auth.granted_by available
    pass
```

**Creating a PAT with scopes:**
```python
from app.services.pat import create_pat

pat = create_pat(
    db=db,
    user_id=user.id,
    name="My Token",
    scopes=["workspaces:read", "workspaces:write"],
    expires_days=30
)
# Returns token string (only time it's visible)
```

**Checking permissions programmatically:**
```python
from app.services.pat import has_permission

if has_permission(db, user_scopes, "workspaces:delete"):
    # User has permission
    pass
```
