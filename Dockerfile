# Honeypot Security System
# Multi-stage build for smaller image size

FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt


# Final stage
FROM python:3.11-slim

LABEL maintainer="Honeypot Security Project"
LABEL description="Honeypot Security System - Detect and analyze attacker behavior"
LABEL version="1.0.0"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    iptables \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create non-root user (but we need root for iptables)
# RUN useradd -m -s /bin/bash honeypot

# Set working directory
WORKDIR /app

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/logs /app/data && \
    chmod +x /app/main.py

# Generate SSH host key if not exists
RUN ssh-keygen -t rsa -b 2048 -f /app/data/ssh_host_key -N "" 2>/dev/null || true

# Copy example config if config doesn't exist
RUN cp -n /app/config/config.example.yaml /app/config/config.yaml 2>/dev/null || true

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Expose ports
# Web Honeypot
EXPOSE 8080
# SSH Honeypot
EXPOSE 2222
# Dashboard
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/')" || exit 1

# Default command
CMD ["python", "main.py"]
