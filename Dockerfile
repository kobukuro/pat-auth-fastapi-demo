# 使用多階段建置 (multi-stage build) 來建立不同用途的映像檔
# Base stage - shared build dependencies
FROM python:3.13-alpine AS base
# 自動建立 /app 資料夾並切換到該目錄
WORKDIR /app
# Install build dependencies (required for bcrypt)
# 以下是編譯 bcrypt 密碼雜湊函式庫所需的C語言編譯工具和相依套件
# --no-cache表示安裝完後不保留快取檔案，減少image大小
RUN apk add --no-cache gcc musl-dev libffi-dev

# Development stage - for local development with docker compose
FROM base AS development
# Install production dependencies
COPY requirements.txt ./
# 利用--no-cache-dir不使用快取，減少image大小，因為也不需要保留快取
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Run migration and start app
# sh: 執行 Alpine 的 shell
# -c: 從字串讀取並執行命令
# alembic upgrade head: 執行 Alembic 的資料庫遷移，確保資料庫結構是最新的
# uvicorn: FastAPI 伺服器
# app.main:app: app/main.py 中的 app 物件
# --host 0.0.0.0: 監聽所有網路介面，這樣外部才能訪問
# --port 8000: 使用 8000 port
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]

# Test stage - includes test dependencies
FROM base AS test
# Install all dependencies (production + dev)
COPY requirements.txt requirements-dev.txt* ./
# -f: 檢查檔案是否存在且為regular file（一般檔案）
RUN pip install --no-cache-dir -r requirements.txt && \
    if [ -f requirements-dev.txt ]; then pip install --no-cache-dir -r requirements-dev.txt; fi
COPY . .
# Default to running tests
# -v: verbose（詳細輸出模式(測試時顯示每個測試檔名)）
CMD ["pytest", "-v"]
