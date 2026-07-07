# ─── Stage 1: Backend ───
FROM python:3.11-slim AS backend

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy and install SDK first (as editable)
COPY kasra-sdk/ /app/kasra-sdk/
RUN pip install --no-cache-dir -e /app/kasra-sdk

# Copy and install main app
COPY kasra/ /app/kasra-app/
RUN pip install --no-cache-dir -e /app/kasra-app

# Data volume
VOLUME ["/data", "/config"]

EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "4"]
