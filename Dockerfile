FROM python:3.13-alpine

WORKDIR /app

# Install build dependencies (required for bcrypt)
RUN apk add --no-cache gcc musl-dev libffi-dev

# Install dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run migration and start app
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
