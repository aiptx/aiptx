# =============================================================================
# AIPT v2 Dockerfile
# =============================================================================
# Multi-stage build for AI-Powered Penetration Testing Framework
#
# Build:   docker build -t aipt-v2 .
# Run:     docker run -p 8000:8000 aipt-v2
# Dev:     docker-compose up -d
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Builder - Install dependencies and build wheels
# -----------------------------------------------------------------------------
FROM python:3.11-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for layer caching
COPY requirements.txt .

# Create virtual environment and install dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir --upgrade pip wheel setuptools && \
    pip install --no-cache-dir -r requirements.txt

# -----------------------------------------------------------------------------
# Stage 2: Runtime - Minimal production image
# -----------------------------------------------------------------------------
FROM python:3.11-slim as runtime

# Labels
LABEL org.opencontainers.image.title="AIPT v2"
LABEL org.opencontainers.image.description="AI-Powered Penetration Testing Framework"
LABEL org.opencontainers.image.version="2.0.0"
LABEL org.opencontainers.image.vendor="AIPT"

# Security: Run as non-root user
RUN groupadd --gid 1000 aipt && \
    useradd --uid 1000 --gid aipt --shell /bin/bash --create-home aipt

# Install runtime dependencies (security tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Network tools
    nmap \
    curl \
    wget \
    dnsutils \
    netcat-openbsd \
    # SSL tools
    openssl \
    ca-certificates \
    # Process tools
    procps \
    # Clean up
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=aipt:aipt . .

# Create necessary directories
RUN mkdir -p /app/data /app/logs /app/reports && \
    chown -R aipt:aipt /app

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    # AIPT Configuration
    AIPT_LOG_LEVEL=INFO \
    AIPT_LOG_FORMAT=json \
    AIPT_OUTPUT_DIR=/app/data \
    AIPT_REPORTS_DIR=/app/reports \
    # API Configuration
    AIPT_API_HOST=0.0.0.0 \
    AIPT_API_PORT=8000

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Switch to non-root user
USER aipt

# Default command - run API server
CMD ["python", "-m", "uvicorn", "aipt_v2.app:app", "--host", "0.0.0.0", "--port", "8000"]

# -----------------------------------------------------------------------------
# Stage 3: Development - Full toolset for development
# -----------------------------------------------------------------------------
FROM runtime as development

# Switch back to root for installations
USER root

# Install development dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    vim \
    # Additional security tools for development
    nikto \
    sqlmap \
    dirb \
    && rm -rf /var/lib/apt/lists/*

# Install dev Python packages
RUN pip install --no-cache-dir \
    pytest \
    pytest-cov \
    pytest-asyncio \
    black \
    ruff \
    mypy \
    ipython

# Switch back to aipt user
USER aipt

# Development command with hot reload
CMD ["python", "-m", "uvicorn", "aipt_v2.app:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
