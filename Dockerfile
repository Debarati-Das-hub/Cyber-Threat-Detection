# Multi-Stage Production Dockerfile for AEGIS-XAI Cyber Threat Platform
FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TF_CPP_MIN_LOG_LEVEL=3 \
    PORT=8000 \
    HOST=0.0.0.0

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY app/ app/
COPY static/ static/
COPY main.py .

# Pre-train baseline models and initialize database
RUN python -c "from app.detection_engine import DetectionEngine; DetectionEngine(); from app.database import init_db; init_db()"

# Expose service port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8000/api/health || exit 1

# Launch FastAPI web console
CMD ["python", "main.py", "--serve", "--port", "8000", "--host", "0.0.0.0"]
