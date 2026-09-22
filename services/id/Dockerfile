FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/src
ENV PATH="/app/.venv/bin:$PATH"

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    zlib1g-dev \
    libjpeg-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY certs/YandexInternalRootCA.crt /usr/local/share/ca-certificates/YandexInternalRootCA.crt
RUN update-ca-certificates

COPY pyproject.toml uv.lock ./
COPY src/ src/
RUN pip install --no-cache-dir uv==0.8.5 && uv sync --frozen --no-dev --no-editable

RUN useradd -m appuser && chown -R appuser /app
USER appuser

EXPOSE 8001

CMD ["sh", "-c", "exec gunicorn app.wsgi:application --config python:app.gunicorn_config --bind 0.0.0.0:${PORT:-8001} --workers ${WEB_CONCURRENCY:-4} --access-logfile - --error-logfile -"]
