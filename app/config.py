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

    # Chunked upload settings
    DEFAULT_CHUNK_SIZE_MB: int = 5  # 5MB default
    MIN_CHUNK_SIZE_MB: int = 1
    MAX_CHUNK_SIZE_MB: int = 10
    CHUNKED_UPLOAD_EXPIRY_HOURS: int = 24
    CHUNKED_UPLOAD_THRESHOLD_MB: int = 50  # Recommend chunked for files > 50MB

    # Rate limiting settings
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_MAX_REQUESTS: int = 60
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    # Pydantic Settings的配置設定，用來控制類別如何讀取環境變數
    # "env_file": ".env"：告訴 Pydantic 要從.env檔案讀取環境變數
    # "extra": "ignore"：處理「環境變數裡有，但Settings類別沒定義」的欄位時，直接忽略多餘的環境變數
    #                    雖然預設也是"ignore"，但明確指定可以增加可讀性，讓人一眼就知道這裡是有意識地忽略多餘的環境變數
    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()
