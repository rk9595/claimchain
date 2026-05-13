# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------------------
# Insurance Agent — LangChain multi-agent RAG protected by LLM-Shield.
# Slim Python image. No secrets baked in; configure entirely via env vars
# (or --env-file). See README.md for the full variable reference.
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=7860

WORKDIR /app

# curl is the only system dep we need (used by HEALTHCHECK below).
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps in a separate layer so source-code changes don't
# bust the pip cache.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Application source. List explicit paths so .env, .git, the local SQLite
# DB, etc. cannot leak in even if .dockerignore is forgotten.
COPY app.py agents.py tools.py db.py seed_db.py rag.py \
     shield_client.py setup_tenant.py red_team.py ./
COPY static/ ./static/
COPY data/   ./data/

# Run as a non-root user. We do TWO things here so this image works on
# both plain Docker (where USER 1001 is honoured) AND on Red Hat
# OpenShift's `restricted` SCC (which ignores the USER directive and
# assigns a random high UID at runtime, e.g. 1000840000):
#
#   1. Create UID 1001 with a writable home — used by Docker/Podman/RunPod.
#   2. Make /app owned by GID 0 (root group) and group-writable. OpenShift's
#      arbitrary runtime UID is always a member of GID 0, so it inherits
#      read/write via the group bit. This is the standard Red Hat
#      "support arbitrary user IDs" pattern.
#
# /app must be writable because db.py creates the SQLite file on first
# start. If you want persistence, mount a PVC at /app/data and set
# GEICO_DB_PATH=/app/data/agent.db.
RUN useradd --uid 1001 --create-home --shell /bin/bash app \
    && chgrp -R 0 /app /home/app \
    && chmod -R g=u /app /home/app
USER 1001

EXPOSE 7860

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/health" || exit 1

CMD ["python", "app.py"]
