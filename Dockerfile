FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends bash ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md /app/
COPY src /app/src
COPY docs /app/docs
COPY examples /app/examples
COPY db /app/db

RUN pip install --no-cache-dir -e ".[db,aws]"

CMD ["veridion-history-service", "--help"]
