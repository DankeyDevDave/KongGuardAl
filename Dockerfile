# Kong Guard AI Docker Container
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    pkg-config \
    default-libmysqlclient-dev \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install additional dependencies for Supabase
RUN pip install --no-cache-dir asyncpg psycopg2-binary

# Copy application files
COPY . .

# Create data directory for SQLite fallback
RUN mkdir -p /app/data

# Expose ports
EXPOSE 8000 5000

# Environment variables
ENV PYTHONPATH=/app
ENV SUPABASE_HOST=${SUPABASE_HOST:-localhost}
ENV SUPABASE_DATABASE=${SUPABASE_DATABASE:-postgres}
ENV SUPABASE_USER=${SUPABASE_USER:-postgres}
ENV SUPABASE_PASSWORD=${SUPABASE_PASSWORD:-postgres}
ENV SUPABASE_PORT=${SUPABASE_PORT:-5432}
ENV KONG_ADMIN_URL=${KONG_ADMIN_URL:-http://localhost:8001}
ENV AI_SERVICE_PORT=${AI_SERVICE_PORT:-5000}
ENV DASHBOARD_PORT=${DASHBOARD_PORT:-8000}

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Start command
CMD ["python", "main.py"]
