FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH" \
    CRYPTODEP_WEB_DATA_DIR=/data \
    SEMGREP_SETTINGS_FILE=/data/semgrep/settings.yml \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0 \
    CRYPTODEP_SKIP_NEO4J=1 \
    CRYPTODEP_DEBUG=0

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ripgrep ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir "uv>=0.9,<1"

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project --no-cache
COPY README.md LICENSE ./
COPY cryptodep ./cryptodep
COPY tests/__init__.py ./tests/__init__.py
COPY tests/eval/__init__.py tests/eval/eval_metrics.py ./tests/eval/
RUN uv sync --frozen --no-dev --no-cache \
    && useradd --create-home --uid 10001 app \
    && mkdir -p /data/semgrep \
    && chown -R app:app /data

WORKDIR /data
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3)"
CMD ["uvicorn", "cryptodep.web.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-access-log"]
