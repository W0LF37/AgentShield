# ============================================================
# AgentShield Security Gateway
# Production Docker Image
# ============================================================

FROM python:3.12-slim


# ------------------------------------------------------------
# Python runtime settings
# ------------------------------------------------------------

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/src

ENV AGENTSHIELD_MAX_INPUT_LENGTH=32000


# ------------------------------------------------------------
# Application directory
# ------------------------------------------------------------

WORKDIR /app


# ------------------------------------------------------------
# Dependencies
# ------------------------------------------------------------

COPY requirements.txt /app/requirements.txt

RUN pip install \
    --no-cache-dir \
    --upgrade pip \
    && pip install \
    --no-cache-dir \
    -r /app/requirements.txt


# ------------------------------------------------------------
# Application files
# ------------------------------------------------------------

COPY src /app/src


# ------------------------------------------------------------
# Runtime directories
# ------------------------------------------------------------

RUN mkdir -p /app/results


# ------------------------------------------------------------
# Non-root user
# ------------------------------------------------------------

RUN addgroup \
    --system \
    agentshield \
    && adduser \
    --system \
    --ingroup agentshield \
    agentshield \
    && chown \
    -R \
    agentshield:agentshield \
    /app

USER agentshield


# ------------------------------------------------------------
# Network
# ------------------------------------------------------------

EXPOSE 8000


# ------------------------------------------------------------
# Health check
# ------------------------------------------------------------

HEALTHCHECK \
    --interval=30s \
    --timeout=5s \
    --start-period=10s \
    --retries=3 \
    CMD python -c \
    "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4)" \
    || exit 1


# ------------------------------------------------------------
# Production server
# ------------------------------------------------------------

CMD ["uvicorn", "agentshield_api:app", "--host", "0.0.0.0", "--port", "8000"]