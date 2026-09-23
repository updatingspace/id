FROM python:3.12-slim AS python-base

FROM python-base AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    zlib1g-dev \
    libjpeg-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml uv.lock ./
RUN pip install --no-cache-dir uv==0.8.5 \
    && uv sync --frozen --no-dev --no-install-project --compile-bytecode

COPY src/ src/
RUN uv sync --frozen --no-dev --no-editable --compile-bytecode \
    && .venv/bin/python -m compileall -q src

FROM python-base AS runtime

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/src
ENV PATH="/app/.venv/bin:$PATH"

# Keep the shared libraries required at runtime, without compilers or headers.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    zlib1g \
    libjpeg62-turbo \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY certs/YandexInternalRootCA.crt /usr/local/share/ca-certificates/YandexInternalRootCA.crt
RUN update-ca-certificates

RUN useradd -m appuser

# Set ownership while copying: a later recursive chown duplicates these files
# in another image layer, including the entire Python environment.
COPY --from=builder --chown=appuser:appuser /app/.venv /app/.venv
COPY --from=builder --chown=appuser:appuser /app/src /app/src
USER appuser

EXPOSE 8001

CMD ["sh", "-c", "exec gunicorn app.wsgi:application --config python:app.gunicorn_config --bind 0.0.0.0:${PORT:-8001} --workers ${WEB_CONCURRENCY:-4} --access-logfile - --error-logfile -"]
