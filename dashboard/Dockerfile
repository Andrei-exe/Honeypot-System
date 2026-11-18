# dashboard = the web page, on port 8050. It gets the alerts from the threat-engine (GET /api/alerts).
FROM python:3.13-slim

# PYTHONUNBUFFERED=1: prints show up in `docker logs` RIGHT AWAY.
# PYTHONDONTWRITEBYTECODE=1: no .pyc files.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# requirements.txt first -> the pip step stays cached as long as the libraries don't change.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Non-root user. The dashboard writes nothing to disk -> it needs no data folder.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app
USER app

ENV PORT=8050
EXPOSE 8050

# Same as the threat-engine: Python as PID 1 ignores SIGTERM -> SIGINT (= Ctrl+C) stops it cleanly.
STOPSIGNAL SIGINT

CMD ["python", "app.py"]
