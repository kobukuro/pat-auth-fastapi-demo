# Base stage - shared build dependencies
FROM python:3.13-alpine AS base
WORKDIR /app
# Install build dependencies (required for bcrypt)
RUN apk add --no-cache gcc musl-dev libffi-dev

# Development stage - for local development with docker compose
FROM base AS development
# Install production dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Run migration and start app
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]

# Test stage - includes test dependencies
FROM base AS test
# Install all dependencies (production + dev)
COPY requirements.txt requirements-dev.txt* ./
RUN pip install --no-cache-dir -r requirements.txt && \
    if [ -f requirements-dev.txt ]; then pip install --no-cache-dir -r requirements-dev.txt; fi
COPY . .
# Default to running tests
CMD ["pytest", "-v"]
