# ──────────────────────────────────────────────────────────────────────────────
# QVis — Quantum Threat Topology Engine
# Multi-stage Docker build with security hardening
# ──────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies only (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Metadata
LABEL maintainer="QVis Team"
LABEL description="Real-time quantum threat topology visualization engine"
LABEL org.opencontainers.image.source="https://github.com/f2025408135-cyber/qvis"

# Create non-root user for security
RUN groupadd --gid 1000 qvis && \
    useradd --uid 1000 --gid qvis --create-home --shell /bin/false qvis

# Copy Python dependencies from builder stage
COPY --from=builder /install /usr/local

# Create app directory with correct ownership
WORKDIR /app
COPY --chown=qvis:qvis . .

# Create writable directories for non-root operation
RUN mkdir -p /app/.qvis-data && chown qvis:qvis /app/.qvis-data

# Switch to non-root user
USER qvis

# Expose the application port
EXPOSE 8000

# Health check — verify the API is responsive
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')" || exit 1

# Default entrypoint — runs the FastAPI server with uvicorn
ENTRYPOINT ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
CMD []
