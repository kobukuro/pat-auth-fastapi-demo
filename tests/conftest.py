import pytest
from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine, get_db
from app.dependencies.storage import get_storage
from app.main import app
from app.models.scope import Scope
from app.storage.local import LocalStorageBackend


class TestStorageBackend(LocalStorageBackend):
    """
    Test-compatible storage backend that handles both sync and async file streams.

    In tests, TestClient uses sync SpooledTemporaryFile instead of async iterators.
    This backend adapts to handle both cases.
    """

    async def save_file(self, file_id: str, file_stream, content_type: str) -> str:
        """
        Save file, handling both sync and async streams.

        In test environment with TestClient, file_stream is a sync SpooledTemporaryFile.
        In production, it's an async iterator.
        """
        # Check if stream is already async (has __aiter__)
        if hasattr(file_stream, "__aiter__"):
            # Production path: use async iteration
            return await super().save_file(file_id, file_stream, content_type)

        # Test path: sync file - use synchronous file operations
        import os
        from pathlib import Path

        file_path = self._get_file_path(file_id)
        self._ensure_directory_exists(file_path)

        chunk_size = 64 * 1024  # 64KB
        total_size = 0

        try:
            with open(file_path, "wb") as f:
                while True:
                    chunk = file_stream.read(chunk_size)
                    if not chunk:
                        break
                    total_size += len(chunk)

                    if total_size > self.max_size_bytes:
                        f.close()
                        if os.path.exists(file_path):
                            os.remove(file_path)
                        from app.storage.exceptions import FileSizeExceededError
                        raise FileSizeExceededError(total_size, self.max_size_bytes)

                    f.write(chunk)

        except Exception as e:
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except Exception:
                    pass
            raise type(e)(f"Failed to save file: {str(e)}") from e

        return str(file_path)


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    """Run Alembic migrations at the start of the test session."""
    from alembic import command
    from alembic.config import Config
    import os

    # Configure Alembic to run migrations
    alembic_cfg = Config(os.path.join(os.getcwd(), "alembic.ini"))

    # Run all migrations to head
    # This ensures migrations are tested and matches production environment
    command.upgrade(alembic_cfg, "head")

    yield

    # Cleanup: drop all tables after ALL test sessions complete
    # Note: Don't use Base.metadata.drop_all() as it may not properly handle
    # migrations and can leave the database in an inconsistent state
    # Instead, use alembic downgrade to base
    try:
        command.downgrade(alembic_cfg, "base")
    except Exception:
        # If downgrade fails, fall back to drop_all and reset Alembic version state
        Base.metadata.drop_all(bind=engine)
        try:
            # Ensure Alembic does not think the DB is still at head
            command.stamp(alembic_cfg, "base")
        except Exception:
            # If stamping fails, leave teardown best-effort without raising
            pass


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
    """Test client with database and storage dependency overrides."""

    def override_get_db():
        yield db

    def override_get_storage():
        # Use test-compatible storage that handles sync file streams
        return TestStorageBackend()

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_storage] = override_get_storage
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Reset the rate limiter before each test to avoid interference."""
    from app.middleware.rate_limit import rate_limiter
    rate_limiter._requests.clear()
    rate_limiter._locks.clear()
    yield
