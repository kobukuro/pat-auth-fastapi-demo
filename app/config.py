from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Database settings
    DATABASE_URL: str

    # JWT settings
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 30

    # Storage settings
    STORAGE_BACKEND: str = "local"  # local | s3 (future)
    STORAGE_BASE_PATH: str = "app/storage/data"
    MAX_UPLOAD_SIZE_MB: int = 1000
    ALLOWED_FCS_EXTENSIONS: list[str] = [".fcs"]
    ALLOWED_FCS_CONTENT_TYPES: list[str] = [
        "application/octet-stream",
        "application/fcs",
    ]

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()
