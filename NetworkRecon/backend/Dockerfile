# ===========================================
# Backend Dockerfile - Multi-stage Build
# ===========================================

# Builder stage
FROM python:3.11-slim AS builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Create virtual environment and install dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim AS production

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libexpat1 \
    nmap \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install sqlmap
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
    chmod +x /opt/sqlmap/sqlmap.py && \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY --chown=appuser:appuser . .

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health')" || exit 1

# Run application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
