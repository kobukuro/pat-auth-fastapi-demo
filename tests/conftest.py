import pytest
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine, get_db
from app.main import app
from app.models.scope import Scope


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    """Create all tables and seed scope data at the start of the test session."""
    Base.metadata.create_all(bind=engine)

    # Seed scope data (same data as in alembic migration)
    db = SessionLocal()
    try:
        if db.query(Scope).count() == 0:
            scopes = [
                Scope(resource='workspaces', action='read', name='workspaces:read', level=1),
                Scope(resource='workspaces', action='write', name='workspaces:write', level=2),
                Scope(resource='workspaces', action='delete', name='workspaces:delete', level=3),
                Scope(resource='workspaces', action='admin', name='workspaces:admin', level=4),
                Scope(resource='users', action='read', name='users:read', level=1),
                Scope(resource='users', action='write', name='users:write', level=2),
                Scope(resource='fcs', action='read', name='fcs:read', level=1),
                Scope(resource='fcs', action='write', name='fcs:write', level=2),
                Scope(resource='fcs', action='analyze', name='fcs:analyze', level=3),
            ]
            db.add_all(scopes)
            db.commit()
    finally:
        db.close()

    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db():
    """Each test uses an independent transaction that gets rolled back after."""
    connection = engine.connect()
    transaction = connection.begin()
    session = SessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db):
    """Test client with database dependency override."""

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
