FROM python:3.13-alpine

WORKDIR /app

# Install build dependencies (required for bcrypt)
RUN apk add --no-cache gcc musl-dev libffi-dev

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy project files
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen

COPY . .

# Run migration and start app
CMD ["sh", "-c", "uv run alembic upgrade head && uv run uvicorn app.main:app --host 0.0.0.0 --port 8000"]
