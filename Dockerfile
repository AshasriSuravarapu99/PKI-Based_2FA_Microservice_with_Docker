# --------------------------
# Stage 1 — Builder
# --------------------------
FROM python:3.11-slim AS builder

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --------------------------
# Stage 2 — Runtime
# --------------------------
FROM python:3.11-slim

ENV TZ=UTC

RUN apt-get update && \
    apt-get install -y cron tzdata && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY . .

RUN mkdir -p /data && mkdir -p /cron
RUN chmod 755 /data /cron

COPY cron/2fa-cron /cron/2fa-cron
RUN chmod 644 /cron/2fa-cron && crontab /cron/2fa-cron

EXPOSE 8080

CMD service cron start && uvicorn app:app --host 0.0.0.0 --port 8080
